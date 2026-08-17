# P3 Controller — AI Agent Connection Instructions

## Architecture
- P3 Controller = FastAPI control plane at localhost:8443 (SQLite + Ed25519 auth + Docker Warden)
- Replaced old GitHub-relay (insecure). GitHub is now credential-only via broker.
- Agent connects via HTTPS tunnel (ngrok or Cloudflare).

## Current Deployment
- Repo: https://github.com/Kotokvit/p3-controller
- Server: http://127.0.0.1:8443
- Tunnel: https://retreat-defrost-dripping.ngrok-free.dev → localhost:8443
- Admin key: p3-admin-local
- Python: .venv/bin/python3 (NOT system python, Arch Linux blocks PEP 668)
- Run commands: `PYTHONPATH=. .venv/bin/python3 -m p3controller.cli.main ...`
- Fish shell — NO `source .venv/bin/activate`, use `.venv/bin/` directly

## Active Agents
- ag_4d09cea1 (remote-ai, developer profile) — ENROLLED, heartbeat 200 via tunnel
  - Private key NOT saved externally (generated in-memory during enrollment test)
  - Need to re-create + enroll for persistent connection

## Full Agent Enrollment Flow
1. Create agent: POST /api/v1/admin/agents {name, profile} with X-Admin-Key
2. Get enrollment_token from response
3. Generate Ed25519 keypair: AgentIdentity.generate(agent_id)
4. POST /api/v1/agents/enroll {enrollment_token, agent_name, public_key}
5. Token destroyed. Agent authenticates with Ed25519 signatures forever.

## Request Signing
- sign_request(agent_id, private_key, method, path, body_bytes)
- Headers: Authorization: P3 <agent_id>:<timestamp>:<nonce>:<signature>
- Replay protection: nonce cached in DB, duplicate rejected

## Next Steps for AI Agent
1. Clone repo: git clone https://github.com/Kotokvit/p3-controller.git
2. Create venv: python3 -m venv .venv && .venv/bin/pip install -e .
3. Create new agent via tunnel: POST /api/v1/admin/agents
4. Enroll with Ed25519 handshake
5. Heartbeat loop: POST /api/v1/agents/heartbeat (every 30s)
6. Command poll: GET /api/v1/agents/commands
7. Execute in Docker Warden sandbox
8. Submit result: POST /api/v1/agents/commands/{id}/result

## Key Files
- p3controller/security/crypto.py — Ed25519 identity, key parsing
- p3controller/security/protocol.py — request signing/verification
- p3controller/server/app.py — FastAPI endpoints
- p3controller/storage/database.py — SQLite schema + Fernet encryption
- p3controller/warden/manager.py — Docker sandbox
- tests/e2e.py — 39 security tests
- tests/server_test.py — 13 HTTP integration tests
