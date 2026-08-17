"""
P3 Controller Server — FastAPI control plane.

Endpoints:
  POST /api/v1/agents/enroll          — one-time enrollment
  POST /api/v1/agents/auth            — authenticate (verify Ed25519 signature)
  POST /api/v1/agents/heartbeat       — keep-alive + status
  GET  /api/v1/agents/{id}/config     — get agent config + permissions
  GET  /api/v1/agents/{id}/commands   — poll for pending commands
  POST /api/v1/agents/{id}/commands/{cmd_id}/result — submit command result
  GET  /api/v1/agents/{id}/credentials/github — get scoped GitHub credential
  POST /api/v1/agents/{id}/events     — submit events

  POST /api/v1/admin/agents           — create agent (from CLI)
  POST /api/v1/admin/commands         — queue command for agent
  GET  /api/v1/admin/agents           — list agents
  POST /api/v1/admin/github/credentials — add GitHub PAT

All agent requests require Ed25519-signed authentication.
Admin endpoints use API key (for CLI).
"""

import base64
import json
import time
from typing import Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..security.crypto import (
    AgentIdentity,
    EnrollmentToken,
    generate_agent_id,
    generate_agent_key,
    generate_command_id,
    generate_nonce,
    hash_secret,
    parse_agent_key,
)
from ..security.protocol import (
    SignedRequest,
    sign_request,
    verify_request,
    parse_auth_header,
    body_sha256,
    canonical_message,
    format_auth_header,
)
from ..security.permissions import Permissions, PROFILES, get_profile
from ..storage.database import P3Database
from ..warden.manager import Warden, CellSpec
from ..github_rel.provider import GitHubCredentialProvider
from ..config import P3Config


# ── Pydantic Models ────────────────────────────────────────
class EnrollRequest(BaseModel):
    enrollment_token: str
    agent_name: str
    public_key: str   # base64-encoded Ed25519 public key
    platform: str = "linux"
    version: str = "1.0.0"

class EnrollResponse(BaseModel):
    agent_id: str
    status: str
    permissions: dict
    server_url: str

class HeartbeatRequest(BaseModel):
    status: str = "active"
    running_commands: list[str] = []

class CommandSubmit(BaseModel):
    agent_id: str
    argv: list[str]
    cwd: str = "/workspace"
    timeout: int = 3600
    profile: str = "developer"

class CommandResult(BaseModel):
    command_id: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False

class CreateAgentRequest(BaseModel):
    name: str
    profile: str = "developer"

class CreateAgentResponse(BaseModel):
    agent_id: str
    agent_key: str
    enrollment_token: str
    expires_in: int

class AddGitHubCredentialRequest(BaseModel):
    token: str
    token_type: str = "fine_grained"

class GitHubCredentialRequest(BaseModel):
    repository: str
    operation: str  # clone|push|pull|issue_create|pr_create


# ── App Factory ────────────────────────────────────────────
def create_app(config: Optional[P3Config] = None) -> FastAPI:
    cfg = config or P3Config()
    cfg.load()

    app = FastAPI(
        title="P3 Controller",
        version="1.0.0",
        description="Secure AI Agent Control Plane",
    )

    # Initialize components
    master_key = cfg.get_master_key()
    db = P3Database(cfg.db_path, master_key=master_key)
    warden = Warden()
    github_provider = GitHubCredentialProvider(db)
    admin_api_key = hash_secret("p3-admin-local")  # default admin key for CLI

    # Store in app state
    app.state.cfg = cfg
    app.state.db = db
    app.state.warden = warden
    app.state.github = github_provider
    app.state.admin_api_key = admin_api_key

    @app.on_event("startup")
    async def startup():
        await db.init()

    # ── Auth Middleware ─────────────────────────────────────
    async def verify_agent_auth(request: Request) -> dict:
        """
        Verify Ed25519-signed request from agent.
        Returns agent dict if valid, raises 401 otherwise.
        """
        auth_header = request.headers.get("Authorization", "")
        signed = parse_auth_header(auth_header)
        if not signed:
            raise HTTPException(401, "Missing or invalid Authorization header")

        # Get agent from DB
        agent = await db.get_agent(signed.agent_id)
        if not agent or agent["status"] != "active":
            raise HTTPException(401, "Agent not found or not active")

        if not agent["public_key"]:
            raise HTTPException(401, "Agent not enrolled (no public key)")

        # Reconstruct public key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_key = Ed25519PublicKey.from_public_bytes(agent["public_key"])

        # Fill in request details
        body = await request.body()
        signed.method = request.method
        signed.path = str(request.url.path)
        signed.body_hash = body_sha256(body)

        # Verify signature + timestamp
        if not verify_request(signed, pub_key, clock_skew=cfg.get("security", "request_clock_skew", default=30)):
            raise HTTPException(401, "Invalid signature or expired timestamp")

        # Check nonce (replay protection)
        if not await db.check_and_store_nonce(signed.nonce):
            raise HTTPException(401, "Replay detected — nonce already used")

        # Update last seen
        await db.update_last_seen(signed.agent_id)

        return agent

    async def verify_admin_auth(request: Request) -> bool:
        """Verify admin API key (for CLI access)."""
        auth = request.headers.get("X-Admin-Key", "")
        if hash_secret(auth) == admin_api_key:
            return True
        # Also accept direct key for convenience
        if auth == "p3-admin-local":
            return True
        raise HTTPException(403, "Invalid admin key")

    # ── Health ──────────────────────────────────────────────
    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "1.0.0"}

    # ── Agent Endpoints ────────────────────────────────────

    @app.post("/api/v1/agents/enroll", response_model=EnrollResponse)
    async def enroll(req: EnrollRequest):
        """One-time enrollment. Consumes enrollment token, registers agent's public key."""
        token_hash = hash_secret(req.enrollment_token)

        # Check enrollment token
        token_data = await db.use_enrollment_token(token_hash)
        if not token_data:
            raise HTTPException(401, "Invalid, expired, or already-used enrollment token")

        agent_id = token_data["agent_id"]

        # Store agent's Ed25519 public key
        try:
            pub_key_bytes = base64.b64decode(req.public_key)
            if len(pub_key_bytes) != 32:
                raise ValueError("Ed25519 public key must be 32 bytes")
        except (ValueError, Exception) as e:
            raise HTTPException(400, f"Invalid public key: {e}")

        await db.set_agent_public_key(agent_id, pub_key_bytes)

        # Get permissions
        perms = await db.get_permissions(agent_id)
        perm_dict = {k: bool(v) for k, v in perms.items() if k != "agent_id"}

        # Audit
        await db.audit("agent.enrolled", agent_id, {
            "agent_name": req.agent_name,
            "platform": req.platform,
            "version": req.version,
        })

        return EnrollResponse(
            agent_id=agent_id,
            status="active",
            permissions=perm_dict,
            server_url=f"https://{cfg.get('server', 'host', default='127.0.0.1')}:{cfg.get('server', 'port', default=8443)}",
        )

    @app.post("/api/v1/agents/heartbeat")
    async def heartbeat(req: HeartbeatRequest, agent: dict = Depends(verify_agent_auth)):
        """Keep-alive + status update."""
        await db.audit("agent.heartbeat", agent["id"], {"status": req.status})
        return {"status": "ok", "timestamp": time.time()}

    @app.get("/api/v1/agents/{agent_id}/config")
    async def get_config(agent_id: str, agent: dict = Depends(verify_agent_auth)):
        """Get agent configuration + permissions."""
        if agent["id"] != agent_id:
            raise HTTPException(403, "Agent ID mismatch")

        perms = await db.get_permissions(agent_id)
        github_access = await db.get_agent_github_access(agent_id)

        return {
            "agent_id": agent_id,
            "profile": agent["profile"],
            "permissions": {k: bool(v) for k, v in perms.items() if k != "agent_id"},
            "github_access": github_access,
        }

    @app.get("/api/v1/agents/{agent_id}/commands")
    async def get_commands(agent_id: str, agent: dict = Depends(verify_agent_auth)):
        """Poll for pending commands."""
        if agent["id"] != agent_id:
            raise HTTPException(403, "Agent ID mismatch")

        commands = await db.get_pending_commands(agent_id)
        return {"commands": commands}

    @app.post("/api/v1/agents/{agent_id}/commands/{command_id}/result")
    async def submit_result(
        agent_id: str,
        command_id: str,
        result: CommandResult,
        agent: dict = Depends(verify_agent_auth),
    ):
        """Submit command execution result."""
        if agent["id"] != agent_id:
            raise HTTPException(403, "Agent ID mismatch")

        await db.store_command_result(
            command_id=command_id,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            truncated=result.truncated,
        )
        status = "completed" if result.exit_code == 0 else "failed"
        await db.update_command_status(command_id, status)

        await db.audit("command.completed", agent_id, {
            "command_id": command_id,
            "exit_code": result.exit_code,
            "truncated": result.truncated,
        })

        return {"status": "ok"}

    @app.post("/api/v1/agents/{agent_id}/credentials/github")
    async def get_github_credential(
        agent_id: str,
        req: GitHubCredentialRequest,
        agent: dict = Depends(verify_agent_auth),
    ):
        """
        Get scoped GitHub credential for a specific repository and operation.
        Agent NEVER receives the PAT directly — only through this broker.
        """
        if agent["id"] != agent_id:
            raise HTTPException(403, "Agent ID mismatch")

        cred = await github_provider.get_credential_for_agent(
            agent_id=agent_id,
            repository=req.repository,
            operation=req.operation,
        )

        if not cred:
            raise HTTPException(403, f"Access denied: {req.operation} on {req.repository}")

        await db.audit("github.credential_issued", agent_id, {
            "repository": req.repository,
            "operation": req.operation,
            "credential_id": cred.credential_id,
        })

        return {
            "owner": cred.owner,
            "token": cred.token,  # scoped, time-limited
            "repositories": cred.repositories,
        }

    # ── Admin Endpoints ────────────────────────────────────

    @app.post("/api/v1/admin/agents", response_model=CreateAgentResponse)
    async def create_agent(req: CreateAgentRequest, _: bool = Depends(verify_admin_auth)):
        """Create a new agent. Returns agent key + one-time enrollment token."""
        # Generate agent key
        agent_id_tmp = generate_agent_id()  # temporary, will be overwritten by DB
        agent_key = generate_agent_key(agent_id_tmp)
        agent_id, secret = parse_agent_key(agent_key)
        key_hash = hash_secret(secret)

        # Create agent in DB
        actual_id = await db.create_agent(
            name=req.name,
            key_hash=key_hash,
            profile=req.profile,
        )

        # Generate enrollment token
        enroll_ttl = cfg.get("security", "enrollment_ttl", default=600)
        enroll = EnrollmentToken.generate(actual_id, req.name, ttl=enroll_ttl)
        token_hash = hash_secret(enroll.token)

        await db.store_enrollment_token(
            token_hash=token_hash,
            agent_id=actual_id,
            agent_name=req.name,
            expires_at=enroll.expires_at,
        )

        # Audit
        await db.audit("agent.created", actual_id, {
            "name": req.name,
            "profile": req.profile,
        })

        # Reconstruct agent key with actual ID
        final_key = f"p3k_{actual_id}:{secret}"

        return CreateAgentResponse(
            agent_id=actual_id,
            agent_key=final_key,
            enrollment_token=enroll.token,
            expires_in=enroll_ttl,
        )

    @app.get("/api/v1/admin/agents")
    async def list_agents(_: bool = Depends(verify_admin_auth)):
        agents = await db.list_agents()
        # Remove sensitive data
        for a in agents:
            a.pop("key_hash", None)
            a.pop("public_key", None)
        return {"agents": agents}

    @app.post("/api/v1/admin/agents/{agent_id}/revoke")
    async def revoke_agent(agent_id: str, _: bool = Depends(verify_admin_auth)):
        await db.update_agent_status(agent_id, "revoked")
        await db.audit("agent.revoked", agent_id)
        return {"status": "revoked", "agent_id": agent_id}

    @app.post("/api/v1/admin/commands")
    async def queue_command(req: CommandSubmit, _: bool = Depends(verify_admin_auth)):
        """Queue a command for an agent. Command uses argv (never shell string)."""
        # Validate agent exists and is active
        agent = await db.get_agent(req.agent_id)
        if not agent:
            raise HTTPException(404, f"Agent {req.agent_id} not found")
        if agent["status"] != "active":
            raise HTTPException(400, f"Agent {req.agent_id} is {agent['status']}, not active")

        # Validate argv is a proper list (not a shell string)
        if not isinstance(req.argv, list) or len(req.argv) == 0:
            raise HTTPException(400, "argv must be a non-empty list of strings")

        # SECURITY: Check that no argv element looks like shell injection
        for arg in req.argv:
            if not isinstance(arg, str):
                raise HTTPException(400, f"All argv elements must be strings, got {type(arg)}")
            # Basic sanity check (not a security boundary — Warden enforces real isolation)
            if arg.strip() != arg:
                raise HTTPException(400, "argv elements must not have leading/trailing whitespace")

        command_id = generate_command_id()
        await db.create_command(
            command_id=command_id,
            agent_id=req.agent_id,
            argv=req.argv,
            cwd=req.cwd,
            timeout=req.timeout,
        )

        await db.audit("command.queued", req.agent_id, {
            "command_id": command_id,
            "argv": req.argv,
            "cwd": req.cwd,
        })

        return {"command_id": command_id, "status": "pending"}

    @app.post("/api/v1/admin/github/credentials")
    async def add_github_credential(req: AddGitHubCredentialRequest, _: bool = Depends(verify_admin_auth)):
        """Add a GitHub PAT. Token is validated and encrypted before storage."""
        # Validate token with GitHub API
        user_info = await github_provider.validate_token(req.token)
        if not user_info:
            raise HTTPException(400, "Invalid GitHub token — failed authentication")

        # Encrypt and store
        cred_id = await db.add_github_credential(
            owner=user_info["login"],
            token=req.token,
            token_type=req.token_type,
        )

        await db.audit("github.credential_added", details={
            "credential_id": cred_id,
            "owner": user_info["login"],
            "token_type": req.token_type,
        })

        return {
            "credential_id": cred_id,
            "owner": user_info["login"],
            "token_type": req.token_type,
        }

    @app.post("/api/v1/admin/github/credentials/{cred_id}/grant")
    async def grant_agent_github_access(
        cred_id: int,
        agent_id: str = "",
        repositories: str = "[]",
        contents_perm: str = "read",
        issues_perm: str = "read",
        pr_perm: str = "read",
        _: bool = Depends(verify_admin_auth),
    ):
        """Grant an agent access to a GitHub credential for specific repos."""
        repos = json.loads(repositories) if isinstance(repositories, str) else repositories
        await db.set_agent_github_access(
            agent_id=agent_id,
            credential_id=cred_id,
            repositories=repos,
            contents_perm=contents_perm,
            issues_perm=issues_perm,
            pr_perm=pr_perm,
        )
        return {"status": "ok"}

    # ── Error handler ──────────────────────────────────────
    @app.exception_handler(Exception)
    async def general_error(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"error": str(exc)},
        )

    return app
