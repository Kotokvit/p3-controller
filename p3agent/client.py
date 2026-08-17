"""
P3 Agent — client that runs on the remote machine.

Responsibilities:
  1. Enroll with Controller using one-time token
  2. Generate and store Ed25519 identity keypair
  3. Authenticate all requests with Ed25519 signatures
  4. Poll for commands, execute in Docker via Warden, return results
  5. Git credential helper integration
"""

import base64
import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx

from .protocol import AgentProtocol
from .enrollment import AgentEnrollment


# ── Config ─────────────────────────────────────────────────
DEFAULT_AGENT_DIR = Path.home() / ".config" / "p3-agent"


class P3AgentClient:
    """
    Full agent client: enrollment, heartbeat, command execution.
    """

    def __init__(
        self,
        agent_dir: Optional[Path] = None,
        controller_url: str = "https://127.0.0.1:8443",
    ):
        self.agent_dir = agent_dir or DEFAULT_AGENT_DIR
        self.controller_url = controller_url.rstrip("/")
        self.protocol: Optional[AgentProtocol] = None
        self._identity_path = self.agent_dir / "identity.json"
        self._client = httpx.AsyncClient(
            base_url=self.controller_url,
            timeout=30.0,
            verify=False,  # TODO: proper TLS
        )

    def _ensure_dir(self):
        self.agent_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.agent_dir, 0o700)

    # ── Enrollment ─────────────────────────────────────────
    async def enroll(self, enrollment_token: str) -> dict:
        """
        Enroll this agent with Controller.
        Generates Ed25519 keypair, sends public key, receives config.
        """
        self._ensure_dir()

        # Generate identity keypair
        from ..p3controller.security.crypto import AgentIdentity
        identity = AgentIdentity.generate("pending")  # ID assigned by controller

        # Send enrollment request
        enrollment = AgentEnrollment(self._client)
        result = await enrollment.enroll(
            token=enrollment_token,
            public_key=identity.public_key_bytes(),
        )

        if not result:
            raise RuntimeError("Enrollment failed — invalid or expired token")

        # Update identity with assigned agent_id
        identity = AgentIdentity(
            agent_id=result["agent_id"],
            private_key=identity.private_key,
            public_key=identity.public_key,
        )

        # Save identity (private key stored locally, NEVER sent to server)
        self._save_identity(identity, result)

        # Initialize protocol with identity
        self.protocol = AgentProtocol(
            agent_id=identity.agent_id,
            private_key=identity.private_key,
            client=self._client,
        )

        return result

    def _save_identity(self, identity, enroll_result: dict):
        """Save identity to local storage. Private key NEVER leaves this machine."""
        data = {
            "agent_id": identity.agent_id,
            "private_key_b64": base64.b64encode(identity.private_key_bytes()).decode(),
            "public_key_b64": base64.b64encode(identity.public_key_bytes()).decode(),
            "controller_url": self.controller_url,
            "permissions": enroll_result.get("permissions", {}),
            "enrolled_at": time.time(),
        }
        with open(self._identity_path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(self._identity_path, 0o600)

    def load_identity(self) -> bool:
        """Load existing identity from disk."""
        if not self._identity_path.exists():
            return False

        with open(self._identity_path) as f:
            data = json.load(f)

        from ..p3controller.security.crypto import AgentIdentity
        identity = AgentIdentity.from_private_bytes(
            data["agent_id"],
            base64.b64decode(data["private_key_b64"]),
        )

        self.controller_url = data.get("controller_url", self.controller_url)
        self.protocol = AgentProtocol(
            agent_id=identity.agent_id,
            private_key=identity.private_key,
            client=self._client,
        )

        return True

    # ── Heartbeat ──────────────────────────────────────────
    async def heartbeat(self) -> dict:
        """Send keep-alive to Controller."""
        if not self.protocol:
            raise RuntimeError("Not enrolled")
        return await self.protocol.signed_post(
            "/api/v1/agents/heartbeat",
            {"status": "active", "running_commands": []},
        )

    # ── Commands ───────────────────────────────────────────
    async def get_commands(self) -> list[dict]:
        """Poll for pending commands."""
        if not self.protocol:
            raise RuntimeError("Not enrolled")
        result = await self.protocol.signed_get(
            f"/api/v1/agents/{self.protocol.agent_id}/commands",
        )
        return result.get("commands", [])

    async def submit_result(self, command_id: str, exit_code: int,
                            stdout: str, stderr: str, truncated: bool = False) -> dict:
        """Submit command execution result."""
        if not self.protocol:
            raise RuntimeError("Not enrolled")
        return await self.protocol.signed_post(
            f"/api/v1/agents/{self.protocol.agent_id}/commands/{command_id}/result",
            {
                "command_id": command_id,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": truncated,
            },
        )

    # ── Main Loop ──────────────────────────────────────────
    async def run(self, warden=None):
        """
        Main agent loop: heartbeat → poll commands → execute → report.
        Commands execute via Warden (Docker), NEVER on host.
        """
        import asyncio

        if not self.protocol:
            if not self.load_identity():
                raise RuntimeError("Not enrolled — run 'p3-agent enroll <token>' first")

        # Import warden if not provided
        if warden is None:
            from ..p3controller.warden.manager import Warden
            warden = Warden()

        print(f"P3 Agent {self.protocol.agent_id} running...")

        while True:
            try:
                # Heartbeat
                await self.heartbeat()

                # Poll for commands
                commands = await self.get_commands()

                for cmd in commands:
                    # Execute in Docker cell via Warden
                    from ..p3controller.warden.manager import CellSpec
                    from ..p3controller.security.permissions import SandboxConfig

                    spec = CellSpec(
                        agent_id=self.protocol.agent_id,
                        command_id=cmd["id"],
                        argv=cmd["argv"],  # list, NOT shell string
                        cwd=cmd.get("cwd", "/workspace"),
                        timeout=cmd.get("timeout", 3600),
                        config=SandboxConfig(),
                    )

                    result = await warden.execute(spec)

                    # Submit result
                    await self.submit_result(
                        command_id=cmd["id"],
                        exit_code=result.exit_code,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        truncated=result.truncated,
                    )

                # Wait before next poll
                await asyncio.sleep(5)

            except KeyboardInterrupt:
                print("Agent shutting down...")
                break
            except Exception as e:
                print(f"Agent error: {e}")
                await asyncio.sleep(10)
