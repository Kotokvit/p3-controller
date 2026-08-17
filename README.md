# P3 Controller v1

**Secure AI Agent Control Plane** — remote command bridge where AI sandbox executes commands on your PC via an authenticated, encrypted protocol with proper credential isolation.

## Architecture

```
                    YOUR COMPUTER
              ┌──────────────────────┐
              │    P3 Controller     │
              │  ├─ GitHub PAT       │  ← NEVER shared with agent
              │  ├─ Agent Registry   │
              │  ├─ Permissions      │
              │  ├─ Command Queue    │
              │  └─ Audit            │
              └──────────┬───────────┘
                         │
                  TLS + Ed25519
                         │
                         ▼
              ┌──────────────────────┐
              │     P3 Agent         │
              │  ├─ Identity Key     │  ← NOT your GitHub PAT
              │  └─ Protocol         │
              └──────────┬───────────┘
                         │
                    policy only
                         │
                         ▼
              ┌──────────────────────┐
              │      WARDEN          │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │    DOCKER CELL       │
              │  ├─ AI (root inside) │
              │  ├─ Python/Node/GCC  │
              │  ├─ GPU              │
              │  ├─ Internet         │
              │  ├─ GitHub (broker)  │
              │  └─ /workspace       │
              └──────────────────────┘

                 ╳ NO HOST SHELL
                 ╳ NO HOST SECRETS
                 ╳ NO GITHUB PAT
```

## Key Security Principles

| Principle | Implementation |
|-----------|---------------|
| **Agent Key ≠ GitHub Token** | Agent uses `p3k_ag_xxx:secret` credential, never sees PAT |
| **Ed25519 Identity** | Each agent has unique keypair; Controller stores only public key |
| **One-time Enrollment** | `p3e_` token used once, 10-minute TTL, then destroyed |
| **Signed Requests** | Every agent request is Ed25519-signed with timestamp + nonce |
| **Replay Protection** | Nonce cache in DB, duplicate requests rejected |
| **Commands = argv** | `["python3", "train.py"]` — never `shell=True` |
| **All execution in Docker** | Warden creates isolated container; NEVER host shell |
| **host = False always** | v1 has NO host access mode for remote agents |
| **GitHub PAT encrypted** | Fernet-encrypted in SQLite with master key |
| **Agent can't escalate** | Only Controller admin changes permissions |
| **Audit trail** | Every action logged; secrets never appear in audit |

## Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/Kotokvit/p3-controller.git
cd p3-controller
```

### 2. Create Virtual Environment

**Linux (bash/zsh):**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Linux (fish shell — Arch/CachyOS/etc):**
```bash
python3 -m venv .venv
source .venv/bin/activate.fish
```

**Or run directly without activating (works in any shell):**
```bash
# Use .venv/bin/pip and .venv/bin/python3 instead of pip/python3
```

### 3. Install Dependencies

**If venv is activated:**
```bash
pip install tomli_w tomli fastapi uvicorn cryptography aiosqlite httpx typer pydantic docker
```

**Without activation (any shell):**
```bash
.venv/bin/pip install tomli_w tomli fastapi uvicorn cryptography aiosqlite httpx typer pydantic docker
```

### 4. Run Tests

**If venv is activated:**
```bash
PYTHONPATH=. python3 -c "
import asyncio
from tests.e2e import run_e2e_test
from tests.server_test import run_server_test
print('=== E2E Security Test ===')
asyncio.run(run_e2e_test())
print()
print('=== Server Integration Test ===')
asyncio.run(run_server_test())
"
```

**Without activation:**
```bash
PYTHONPATH=. .venv/bin/python3 -c "
import asyncio
from tests.e2e import run_e2e_test
from tests.server_test import run_server_test
print('=== E2E Security Test ===')
asyncio.run(run_e2e_test())
print()
print('=== Server Integration Test ===')
asyncio.run(run_server_test())
"
```

Expected output: **52/52 PASSED**

### 5. Start Controller

```bash
# Activated venv:
p3 server

# Without activation:
.venv/bin/python3 -m p3controller.cli.main server
```

### 6. Add GitHub Credential

```bash
p3 github add
# Enter your fine-grained PAT (never shared with agents)
```

### 7. Create Agent

```bash
p3 agent create my-gpu-agent --profile developer
```

Output:
```
Agent ID:   ag_a1b2c3d4
Agent Key:  p3k_ag_a1b2c3d4:A8sK2...very-long-random...
Enrollment: p3e_xxxxxxxx... (10 minutes)

Run on remote machine:
  p3-agent enroll p3e_xxxxxxxx...
```

### 8. On Remote Machine

```bash
p3-agent enroll p3e_xxxxxxxx...
p3-agent run
```

### 9. Manage

```bash
p3 agent list
p3 agent revoke my-gpu-agent
```

## Permissions Profiles

| Profile | Sandbox | GPU | Network | GitHub | Host |
|---------|---------|-----|---------|--------|------|
| sandbox | ✓ | ✗ | ✗ | ✗ | ✗ |
| developer | ✓ | ✓ | ✓ | ✓ | ✗ |
| trusted | ✓ | ✓ | ✓ | ✓ | ✗ |

**Host access is NEVER available for remote agents in v1.**

## GitHub Credential Broker

Agent never receives your GitHub PAT. Instead:

```
AI → git clone → credential helper → P3 Agent → P3 Controller → PAT
```

Controller checks:
1. Agent has `github` permission
2. Repository is in allowed list
3. Operation is allowed (read/write)
4. Returns scoped credential for this operation only

## Project Structure

```
p3-controller/
├── p3controller/
│   ├── security/
│   │   ├── crypto.py          # Ed25519, Agent Keys, enrollment tokens
│   │   ├── protocol.py        # Request signing, verification, replay
│   │   └── permissions.py     # Capability model, profiles
│   ├── storage/
│   │   └── database.py        # SQLite + Fernet encryption
│   ├── server/
│   │   └── app.py             # FastAPI control plane
│   ├── github_rel/
│   │   └── provider.py        # Credential broker + git helper
│   ├── warden/
│   │   └── manager.py         # Docker sandbox (all commands here)
│   ├── cli/
│   │   └── main.py            # p3 CLI
│   └── config.py              # TOML config + master key
├── p3agent/
│   ├── client.py              # Agent main loop
│   ├── enrollment.py          # One-time handshake
│   ├── protocol.py            # Signed requests
│   └── cli.py                 # p3-agent CLI
└── tests/
    ├── e2e.py                 # 39 security tests
    └── server_test.py         # 13 HTTP integration tests
```

## Test Results

```
E2E Security:     39/39 PASSED
Server Integration: 13/13 PASSED
Total:            52/52 PASSED
```

## What This Fixes (vs Old P3 Bridge)

| Old P3 Bridge | P3 Controller |
|--------------|---------------|
| HMAC exists but never verified | Ed25519 signatures verified on every request |
| GitHub PAT in chat/environment | PAT encrypted in DB, brokered per-request |
| Commands run on host (shell=True) | Commands in Docker cell (argv only) |
| `target=host` escape route | host=False always in v1 |
| XOR encryption fallback | Fernet (AES-128-CBC) or fail-closed |
| Blacklist regex (bypassable) | Docker isolation (kernel-level) |
| Whitelist startswith() (bypassable) | argv list (structured, not shell) |
| Live data in public repo | Controller is local, no repo data |
| No replay protection | Nonce + timestamp + Ed25519 |
| Hardcoded secrets | master.key (0600) + Fernet encryption |
| Three duplicate PC clients | Single agent client |

## Requirements

- Python 3.11+
- Docker (for Warden/sandbox)
- cryptography, fastapi, uvicorn, aiosqlite, httpx, typer

## Remote Access Tunnel

The Controller runs on localhost:8443. For remote AI agent access:

### Option A: ngrok (quick, 2h idle timeout on free tier)
```bash
ngrok http 8443
```

### Option B: Cloudflare Tunnel (stable, no idle timeout, free forever)
```bash
cloudflared tunnel login
cloudflared tunnel create p3-controller
cloudflared tunnel route dns p3-controller <your-subdomain>.<yourdomain>.com
cloudflared tunnel run p3-controller
```

Current tunnel: `https://retreat-defrost-dripping.ngrok-free.dev`

## License

MIT

