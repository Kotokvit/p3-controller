#!/usr/bin/env python3
"""
P3 Agent enrollment + heartbeat — standalone, no typer, no rich.

Usage:
    cd ~/p3-controller
    PYTHONPATH=. .venv/bin/python3 enroll_and_heartbeat.py

What it does:
  1. GET  /health                                  — check controller
  2. POST /api/v1/admin/agents                     — create agent (X-Admin-Key)
  3. Generate Ed25519 keypair locally
  4. POST /api/v1/agents/enroll                     — register public key
  5. Save identity to ~/.config/p3-agent/identity.json  (chmod 0600)
  6. POST /api/v1/agents/heartbeat (Ed25519-signed) — verify auth works

If controller is exposed via tunnel, set CONTROLLER env var:
    CONTROLLER=https://your-tunnel.example.com PYTHONPATH=. .venv/bin/python3 enroll_and_heartbeat.py
"""
import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

import httpx
from p3controller.security.crypto import AgentIdentity
from p3controller.security.protocol import sign_request, format_auth_header

# ── CONFIG ────────────────────────────────────────────────────
CONTROLLER   = os.environ.get("CONTROLLER", "http://127.0.0.1:8443").rstrip("/")
ADMIN_KEY    = os.environ.get("P3_ADMIN_KEY", "p3-admin-local")
AGENT_NAME   = os.environ.get("P3_AGENT_NAME", "remote-ai-claude")
AGENT_PROFILE= os.environ.get("P3_AGENT_PROFILE", "developer")
IDENTITY_DIR = Path.home() / ".config" / "p3-agent"
IDENTITY_PATH= IDENTITY_DIR / "identity.json"


async def main() -> int:
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(IDENTITY_DIR, 0o700)

    async with httpx.AsyncClient(
        base_url=CONTROLLER, timeout=30.0, verify=False,
    ) as cli:

        # 1. Health probe
        try:
            r = await cli.get("/health")
            print(f"[1/5] GET  /health                -> {r.status_code} {r.text[:200]}")
            if r.status_code != 200:
                print("!! Controller not healthy. Is `p3 server` running?")
                return 1
        except Exception as e:
            print(f"[1/5] GET  /health FAILED: {type(e).__name__}: {e}")
            print(f"    CONTROLLER={CONTROLLER}")
            print(f"    Is `p3 server` running? Try: PYTHONPATH=. .venv/bin/python3 -m p3controller.cli.main server")
            return 1

        # 2. Create agent
        r = await cli.post(
            "/api/v1/admin/agents",
            json={"name": AGENT_NAME, "profile": AGENT_PROFILE},
            headers={"X-Admin-Key": ADMIN_KEY},
        )
        print(f"[2/5] POST /api/v1/admin/agents    -> {r.status_code}")
        if r.status_code != 200:
            print(f"     body: {r.text[:500]}")
            return 1
        data = r.json()
        agent_id          = data["agent_id"]
        enrollment_token  = data["enrollment_token"]
        expires_in        = data.get("expires_in", "?")
        agent_key         = data.get("agent_key", "")
        print(f"      agent_id        = {agent_id}")
        print(f"      enrollment_token = {enrollment_token}")
        print(f"      expires_in       = {expires_in}s")
        print(f"      agent_key        = {agent_key[:48]}... (hash-only in DB)")

        # 3. Ed25519 keypair
        identity = AgentIdentity.generate(agent_id)
        pub_b64 = base64.b64encode(identity.public_key_bytes()).decode()
        print(f"[3/5] Ed25519 keypair generated     pub_b64={pub_b64}")

        # 4. Enroll
        enroll_body = {
            "enrollment_token": enrollment_token,
            "agent_name": AGENT_NAME,
            "public_key": pub_b64,
            "platform": "linux",
            "version": "1.0.0",
        }
        body_bytes = json.dumps(enroll_body).encode()
        r = await cli.post(
            "/api/v1/agents/enroll",
            content=body_bytes,
            headers={"Content-Type": "application/json"},
        )
        print(f"[4/5] POST /api/v1/agents/enroll   -> {r.status_code}")
        if r.status_code != 200:
            print(f"     body: {r.text[:500]}")
            return 1
        enroll_result = r.json()

        # Save identity
        identity_data = {
            "agent_id": agent_id,
            "private_key_b64": base64.b64encode(identity.private_key_bytes()).decode(),
            "public_key_b64": pub_b64,
            "controller_url": CONTROLLER,
            "permissions": enroll_result.get("permissions", {}),
            "enrolled_at": time.time(),
        }
        with open(IDENTITY_PATH, "w") as f:
            json.dump(identity_data, f, indent=2)
        os.chmod(IDENTITY_PATH, 0o600)
        print(f"      identity saved to {IDENTITY_PATH}  (chmod 0600)")

        # 5. Signed heartbeat
        hb_path = "/api/v1/agents/heartbeat"
        hb_body = json.dumps({"status": "active", "running_commands": []}).encode()
        signed = sign_request(
            agent_id=agent_id,
            private_key=identity.private_key,
            method="POST",
            path=hb_path,
            body=hb_body,
        )
        r = await cli.post(
            hb_path,
            content=hb_body,
            headers={
                "Authorization": format_auth_header(signed),
                "Content-Type": "application/json",
            },
        )
        print(f"[5/5] POST /api/v1/agents/heartbeat -> {r.status_code} {r.text[:200]}")
        if r.status_code != 200:
            print("!! Enrollment OK but heartbeat failed. Check signature/nonce logic.")
            return 1

        print("\n===========================================")
        print(" SUCCESS — agent enrolled and heartbeat OK")
        print("===========================================")
        print(f"  agent_id    : {agent_id}")
        print(f"  identity    : {IDENTITY_PATH}")
        print(f"  controller  : {CONTROLLER}")
        print(f"  permissions : {enroll_result.get('permissions', {})}")
        print("\nNext: start the polling loop on the agent side:")
        print(f"  PYTHONPATH=. .venv/bin/python3 -m p3agent.cli run")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
