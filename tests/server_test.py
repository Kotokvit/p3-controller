"""
P3 Server Integration Test — tests actual HTTP API with real uvicorn server.

Uses httpx AsyncClient against a running server.
"""

import asyncio
import base64
import json
import tempfile
import time
from pathlib import Path

import httpx

from p3controller.config import P3Config
from p3controller.security.crypto import (
    AgentIdentity,
    generate_agent_key,
    generate_nonce,
    hash_secret,
    parse_agent_key,
)
from p3controller.security.protocol import sign_request, format_auth_header, body_sha256


class ServerTestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def ok(self, name: str):
        self.passed += 1
        print(f"  ✅ {name}")

    def fail(self, name: str, reason: str):
        self.failed += 1
        print(f"  ❌ {name}: {reason}")


async def run_server_test():
    print("=" * 60)
    print("P3 Controller — Server Integration Test")
    print("=" * 60)

    results = ServerTestResult()

    # Setup temp dir
    tmpdir = tempfile.mkdtemp(prefix="p3-server-test-")
    cfg = P3Config(Path(tmpdir))
    cfg.load()
    cfg.get_master_key()
    cfg._config.setdefault("database", {})["path"] = f"{tmpdir}/test.db"
    cfg._config.setdefault("server", {})["host"] = "127.0.0.1"
    cfg._config.setdefault("server", {})["port"] = 18443  # test port

    # Start server in background
    import uvicorn
    from p3controller.server.app import create_app

    app = create_app(cfg)

    config = uvicorn.Config(app, host="127.0.0.1", port=18443, log_level="error")
    server = uvicorn.Server(config)

    # Run server in background task
    server_task = asyncio.create_task(server.serve())

    # Wait for server to start
    await asyncio.sleep(1.0)

    base_url = "http://127.0.0.1:18443"
    admin_headers = {"X-Admin-Key": "p3-admin-local"}

    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:

            # ══════════════════════════════════════════════════════
            # Test 1: Health check
            # ══════════════════════════════════════════════════════
            print("\n[1] Health Check")
            try:
                resp = await client.get("/health")
                assert resp.status_code == 200
                assert resp.json()["status"] == "ok"
                results.ok("Controller health check")
            except Exception as e:
                results.fail("Health Check", str(e))

            # ══════════════════════════════════════════════════════
            # Test 2: Create Agent
            # ══════════════════════════════════════════════════════
            print("\n[2] Create Agent")
            create_data = None
            try:
                resp = await client.post(
                    "/api/v1/admin/agents",
                    json={"name": "test-int-agent", "profile": "developer"},
                    headers=admin_headers,
                )
                assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
                create_data = resp.json()
                assert "agent_id" in create_data
                results.ok("Admin creates agent via HTTP")

                agent_id = create_data["agent_id"]
                enroll_token = create_data["enrollment_token"]
            except Exception as e:
                results.fail("Create Agent", str(e))
                server.should_exit = True
                return False

            # ══════════════════════════════════════════════════════
            # Test 3: Agent Enrollment
            # ══════════════════════════════════════════════════════
            print("\n[3] Agent Enrollment")
            identity = None
            try:
                identity = AgentIdentity.generate(agent_id)
                pub_key_b64 = base64.b64encode(identity.public_key_bytes()).decode()

                resp = await client.post(
                    "/api/v1/agents/enroll",
                    json={
                        "enrollment_token": enroll_token,
                        "agent_name": "test-int-agent",
                        "public_key": pub_key_b64,
                        "platform": "linux",
                        "version": "1.0.0",
                    },
                )
                assert resp.status_code == 200, f"Enroll: {resp.status_code} {resp.text}"
                enroll_data = resp.json()
                assert enroll_data["status"] == "active"
                results.ok("Agent enrolled (Ed25519 handshake)")

                # Second use should fail
                resp2 = await client.post(
                    "/api/v1/agents/enroll",
                    json={
                        "enrollment_token": enroll_token,
                        "agent_name": "test-int-agent",
                        "public_key": pub_key_b64,
                    },
                )
                assert resp2.status_code == 401
                results.ok("Enrollment token — second use REJECTED")
            except Exception as e:
                results.fail("Agent Enrollment", str(e))

            # ══════════════════════════════════════════════════════
            # Test 4: Signed Heartbeat
            # ══════════════════════════════════════════════════════
            print("\n[4] Signed Heartbeat")
            try:
                body = json.dumps({"status": "active", "running_commands": []}).encode()
                signed = sign_request(
                    agent_id=agent_id,
                    private_key=identity.private_key,
                    method="POST",
                    path="/api/v1/agents/heartbeat",
                    body=body,
                )

                resp = await client.post(
                    "/api/v1/agents/heartbeat",
                    content=body,
                    headers={
                        "Authorization": format_auth_header(signed),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 200, f"Heartbeat: {resp.status_code} {resp.text}"
                results.ok("Signed heartbeat accepted")

                # Replay
                resp2 = await client.post(
                    "/api/v1/agents/heartbeat",
                    content=body,
                    headers={
                        "Authorization": format_auth_header(signed),
                        "Content-Type": "application/json",
                    },
                )
                assert resp2.status_code == 401
                results.ok("Replayed request REJECTED (nonce)")
            except Exception as e:
                results.fail("Signed Heartbeat", str(e))

            # ══════════════════════════════════════════════════════
            # Test 5: Command Queue & Poll
            # ══════════════════════════════════════════════════════
            print("\n[5] Command Queue & Poll")
            try:
                resp = await client.post(
                    "/api/v1/admin/commands",
                    json={
                        "agent_id": agent_id,
                        "argv": ["python3", "-c", "print('p3')"],
                        "cwd": "/workspace",
                        "timeout": 60,
                    },
                    headers=admin_headers,
                )
                assert resp.status_code == 200
                cmd_id = resp.json()["command_id"]
                results.ok("Command queued")

                # Poll
                poll_signed = sign_request(
                    agent_id=agent_id,
                    private_key=identity.private_key,
                    method="GET",
                    path=f"/api/v1/agents/{agent_id}/commands",
                )
                resp = await client.get(
                    f"/api/v1/agents/{agent_id}/commands",
                    headers={"Authorization": format_auth_header(poll_signed)},
                )
                assert resp.status_code == 200
                cmds = resp.json().get("commands", [])
                assert len(cmds) >= 1
                results.ok("Agent polls commands")

                # Submit result
                result_body = json.dumps({
                    "command_id": cmd_id, "exit_code": 0,
                    "stdout": "p3\n", "stderr": "", "truncated": False,
                }).encode()
                result_signed = sign_request(
                    agent_id=agent_id,
                    private_key=identity.private_key,
                    method="POST",
                    path=f"/api/v1/agents/{agent_id}/commands/{cmd_id}/result",
                    body=result_body,
                )
                resp = await client.post(
                    f"/api/v1/agents/{agent_id}/commands/{cmd_id}/result",
                    content=result_body,
                    headers={
                        "Authorization": format_auth_header(result_signed),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 200
                results.ok("Command result submitted")
            except Exception as e:
                results.fail("Command Queue & Poll", str(e))

            # ══════════════════════════════════════════════════════
            # Test 6: Revoke Agent
            # ══════════════════════════════════════════════════════
            print("\n[6] Revoke Agent")
            try:
                resp = await client.post(
                    f"/api/v1/admin/agents/{agent_id}/revoke",
                    json={}, headers=admin_headers,
                )
                assert resp.status_code == 200
                results.ok("Agent revoked")

                # Revoked agent rejected
                body = json.dumps({"status": "active"}).encode()
                signed = sign_request(
                    agent_id=agent_id,
                    private_key=identity.private_key,
                    method="POST",
                    path="/api/v1/agents/heartbeat",
                    body=body,
                )
                resp = await client.post(
                    "/api/v1/agents/heartbeat",
                    content=body,
                    headers={
                        "Authorization": format_auth_header(signed),
                        "Content-Type": "application/json",
                    },
                )
                assert resp.status_code == 401
                results.ok("Revoked agent — REJECTED")
            except Exception as e:
                results.fail("Revoke Agent", str(e))

            # ══════════════════════════════════════════════════════
            # Test 7: Unauthorized Access
            # ══════════════════════════════════════════════════════
            print("\n[7] Unauthorized Access")
            try:
                resp = await client.post(
                    "/api/v1/agents/heartbeat",
                    json={"status": "active"},
                )
                assert resp.status_code == 401
                results.ok("No auth — 401")

                resp = await client.get(
                    "/api/v1/admin/agents",
                    headers={"X-Admin-Key": "wrong"},
                )
                assert resp.status_code == 403
                results.ok("Bad admin key — 403")
            except Exception as e:
                results.fail("Unauthorized Access", str(e))

    finally:
        server.should_exit = True
        await asyncio.sleep(0.5)
        try:
            server_task.cancel()
        except Exception:
            pass

    # Summary
    print(f"\n{'='*60}")
    total = results.passed + results.failed
    print(f"Server Integration: {results.passed}/{total} passed, {results.failed} failed")
    if results.failed == 0:
        print("ALL SERVER TESTS PASSED!")
    print(f"{'='*60}")

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return results.failed == 0


if __name__ == "__main__":
    asyncio.run(run_server_test())
