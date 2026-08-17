"""
P3 Database — SQLite async storage for agents, enrollment, permissions, audit, GitHub credentials.

Master key encrypts GitHub PATs. DB never stores plaintext secrets.
"""

import aiosqlite
import time
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

from p3controller.security.crypto import hash_secret, generate_agent_id


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id              TEXT PRIMARY KEY,       -- ag_xxxxxxxx
    name            TEXT NOT NULL UNIQUE,
    public_key      BLOB,                   -- Ed25519 public key (NULL until enrollment)
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending|active|revoked
    profile         TEXT NOT NULL DEFAULT 'sandbox',  -- sandbox|developer|trusted
    created_at      REAL NOT NULL,
    last_seen       REAL,
    key_hash        TEXT NOT NULL            -- SHA-256 of agent key secret
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash      TEXT PRIMARY KEY,       -- SHA-256 of enrollment token
    agent_id        TEXT NOT NULL REFERENCES agents(id),
    agent_name      TEXT NOT NULL,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS permissions (
    agent_id        TEXT PRIMARY KEY REFERENCES agents(id),
    sandbox         INTEGER NOT NULL DEFAULT 1,
    gpu             INTEGER NOT NULL DEFAULT 0,
    network         INTEGER NOT NULL DEFAULT 0,
    host            INTEGER NOT NULL DEFAULT 0,
    github          INTEGER NOT NULL DEFAULT 0,
    workspace_rw    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS github_credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    owner           TEXT NOT NULL,
    encrypted_token TEXT NOT NULL,           -- Fernet-encrypted PAT
    token_type      TEXT NOT NULL DEFAULT 'fine_grained',  -- fine_grained|classic|app
    created_at      REAL NOT NULL,
    expires_at      REAL                    -- NULL = no expiry
);

CREATE TABLE IF NOT EXISTS github_agent_access (
    agent_id        TEXT NOT NULL REFERENCES agents(id),
    credential_id   INTEGER NOT NULL REFERENCES github_credentials(id),
    repositories    TEXT NOT NULL DEFAULT '[]',  -- JSON array of "owner/repo"
    contents_perm   TEXT NOT NULL DEFAULT 'read', -- read|write
    issues_perm     TEXT NOT NULL DEFAULT 'read',
    pr_perm         TEXT NOT NULL DEFAULT 'read',
    PRIMARY KEY (agent_id, credential_id)
);

CREATE TABLE IF NOT EXISTS commands (
    id              TEXT PRIMARY KEY,       -- cmd_xxxxxx_timestamp
    agent_id        TEXT NOT NULL REFERENCES agents(id),
    argv            TEXT NOT NULL,          -- JSON array of strings
    cwd             TEXT NOT NULL DEFAULT '/workspace',
    timeout         INTEGER NOT NULL DEFAULT 3600,
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending|running|completed|failed|timeout
    created_at      REAL NOT NULL,
    started_at      REAL,
    finished_at     REAL
);

CREATE TABLE IF NOT EXISTS command_results (
    command_id      TEXT PRIMARY KEY REFERENCES commands(id),
    exit_code       INTEGER,
    stdout          TEXT NOT NULL DEFAULT '',
    stderr          TEXT NOT NULL DEFAULT '',
    truncated       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event           TEXT NOT NULL,
    agent_id        TEXT,
    details         TEXT,                   -- JSON
    timestamp       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS nonce_cache (
    nonce           TEXT PRIMARY KEY,
    expires_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_commands_agent ON commands(agent_id);
CREATE INDEX IF NOT EXISTS idx_nonce_expires ON nonce_cache(expires_at);
"""


class P3Database:
    def __init__(self, db_path: str | Path, master_key: Optional[bytes] = None):
        self.db_path = str(db_path)
        self._fernet: Optional[Fernet] = None
        if master_key:
            self._fernet = Fernet(master_key)

    def _encrypt(self, plaintext: str) -> str:
        if self._fernet is None:
            raise RuntimeError("No master key — cannot encrypt")
        return self._fernet.encrypt(plaintext.encode()).decode()

    def _decrypt(self, ciphertext: str) -> str:
        if self._fernet is None:
            raise RuntimeError("No master key — cannot decrypt")
        return self._fernet.decrypt(ciphertext.encode()).decode()

    async def init(self):
        """Create tables if not exist."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(DB_SCHEMA)
            await db.commit()

    # ── Agents ─────────────────────────────────────────────
    async def create_agent(self, name: str, key_hash: str, profile: str = "sandbox") -> str:
        """Create agent, return agent_id."""
        agent_id = generate_agent_id()
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO agents (id, name, public_key, status, profile, created_at, key_hash) "
                "VALUES (?, ?, NULL, 'pending', ?, ?, ?)",
                (agent_id, name, profile, now, key_hash),
            )
            # Default permissions based on profile
            perms = self._default_permissions(profile)
            await db.execute(
                "INSERT INTO permissions (agent_id, sandbox, gpu, network, host, github, workspace_rw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (agent_id, perms["sandbox"], perms["gpu"], perms["network"],
                 perms["host"], perms["github"], perms["workspace_rw"]),
            )
            await db.commit()
        return agent_id

    @staticmethod
    def _default_permissions(profile: str) -> dict:
        profiles = {
            "sandbox":   {"sandbox": 1, "gpu": 0, "network": 0, "host": 0, "github": 0, "workspace_rw": 1},
            "developer": {"sandbox": 1, "gpu": 1, "network": 1, "host": 0, "github": 1, "workspace_rw": 1},
            "trusted":   {"sandbox": 1, "gpu": 1, "network": 1, "host": 0, "github": 1, "workspace_rw": 1},
        }
        return profiles.get(profile, profiles["sandbox"])

    async def get_agent(self, agent_id: str) -> Optional[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_agent_by_key_hash(self, key_hash: str) -> Optional[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM agents WHERE key_hash = ?", (key_hash,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def list_agents(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM agents ORDER BY created_at DESC")
            return [dict(r) for r in await cur.fetchall()]

    async def set_agent_public_key(self, agent_id: str, public_key: bytes):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE agents SET public_key = ?, status = 'active' WHERE id = ?",
                (public_key, agent_id),
            )
            await db.commit()

    async def update_agent_status(self, agent_id: str, status: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE agents SET status = ? WHERE id = ?", (status, agent_id))
            await db.commit()

    async def update_last_seen(self, agent_id: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (time.time(), agent_id))
            await db.commit()

    # ── Enrollment ─────────────────────────────────────────
    async def store_enrollment_token(self, token_hash: str, agent_id: str, agent_name: str,
                                      expires_at: float):
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO enrollment_tokens (token_hash, agent_id, agent_name, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (token_hash, agent_id, agent_name, now, expires_at),
            )
            await db.commit()

    async def use_enrollment_token(self, token_hash: str) -> Optional[dict]:
        """Mark enrollment token as used, return agent info. One-time only."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM enrollment_tokens WHERE token_hash = ? AND used = 0",
                (token_hash,),
            )
            row = await cur.fetchone()
            if not row:
                return None
            data = dict(row)
            if time.time() > data["expires_at"]:
                return None
            await db.execute("UPDATE enrollment_tokens SET used = 1 WHERE token_hash = ?", (token_hash,))
            await db.commit()
        return data

    # ── Permissions ────────────────────────────────────────
    async def get_permissions(self, agent_id: str) -> Optional[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM permissions WHERE agent_id = ?", (agent_id,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def update_permissions(self, agent_id: str, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [agent_id]
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(f"UPDATE permissions SET {sets} WHERE agent_id = ?", vals)
            await db.commit()

    # ── GitHub Credentials ─────────────────────────────────
    async def add_github_credential(self, owner: str, token: str,
                                     token_type: str = "fine_grained",
                                     expires_at: Optional[float] = None) -> int:
        """Encrypt and store GitHub PAT. Returns credential_id."""
        encrypted = self._encrypt(token)
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "INSERT INTO github_credentials (owner, encrypted_token, token_type, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (owner, encrypted, token_type, now, expires_at),
            )
            await db.commit()
            return cur.lastrowid

    async def get_github_credential(self, credential_id: int) -> Optional[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM github_credentials WHERE id = ?", (credential_id,)
            )
            row = await cur.fetchone()
            if not row:
                return None
            data = dict(row)
            data["token"] = self._decrypt(data["encrypted_token"])
            return data

    async def list_github_credentials(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT id, owner, token_type, created_at, expires_at FROM github_credentials")
            return [dict(r) for r in await cur.fetchall()]

    async def set_agent_github_access(self, agent_id: str, credential_id: int,
                                       repositories: list[str],
                                       contents_perm: str = "read",
                                       issues_perm: str = "read",
                                       pr_perm: str = "read"):
        import json
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO github_agent_access "
                "(agent_id, credential_id, repositories, contents_perm, issues_perm, pr_perm) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, credential_id, json.dumps(repositories), contents_perm, issues_perm, pr_perm),
            )
            await db.commit()

    async def get_agent_github_access(self, agent_id: str) -> list[dict]:
        import json
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM github_agent_access WHERE agent_id = ?", (agent_id,)
            )
            results = []
            for r in await cur.fetchall():
                d = dict(r)
                d["repositories"] = json.loads(d["repositories"])
                results.append(d)
            return results

    # ── Commands ───────────────────────────────────────────
    async def create_command(self, command_id: str, agent_id: str,
                              argv: list[str], cwd: str = "/workspace",
                              timeout: int = 3600):
        import json
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO commands (id, agent_id, argv, cwd, timeout, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (command_id, agent_id, json.dumps(argv), cwd, timeout, now),
            )
            await db.commit()

    async def get_pending_commands(self, agent_id: str) -> list[dict]:
        import json
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM commands WHERE agent_id = ? AND status = 'pending' ORDER BY created_at",
                (agent_id,),
            )
            results = []
            for r in await cur.fetchall():
                d = dict(r)
                d["argv"] = json.loads(d["argv"])
                results.append(d)
            return results

    async def update_command_status(self, command_id: str, status: str):
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            if status == "running":
                await db.execute(
                    "UPDATE commands SET status = ?, started_at = ? WHERE id = ?",
                    (status, now, command_id),
                )
            elif status in ("completed", "failed", "timeout"):
                await db.execute(
                    "UPDATE commands SET status = ?, finished_at = ? WHERE id = ?",
                    (status, now, command_id),
                )
            else:
                await db.execute("UPDATE commands SET status = ? WHERE id = ?", (status, command_id))
            await db.commit()

    async def store_command_result(self, command_id: str, exit_code: int,
                                    stdout: str, stderr: str, truncated: bool = False):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO command_results (command_id, exit_code, stdout, stderr, truncated) "
                "VALUES (?, ?, ?, ?, ?)",
                (command_id, exit_code, stdout, stderr, int(truncated)),
            )
            await db.commit()

    # ── Audit ──────────────────────────────────────────────
    async def audit(self, event: str, agent_id: Optional[str] = None, details: Optional[dict] = None):
        import json
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO audit_events (event, agent_id, details, timestamp) VALUES (?, ?, ?, ?)",
                (event, agent_id, json.dumps(details) if details else None, time.time()),
            )
            await db.commit()

    # ── Nonce / Replay Protection ──────────────────────────
    async def check_and_store_nonce(self, nonce: str, ttl: int = 300) -> bool:
        """Return True if nonce is fresh (not seen before), False if replay."""
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            # Clean expired nonces
            await db.execute("DELETE FROM nonce_cache WHERE expires_at < ?", (now,))
            # Check if nonce exists
            cur = await db.execute("SELECT 1 FROM nonce_cache WHERE nonce = ?", (nonce,))
            if await cur.fetchone():
                return False  # replay!
            await db.execute(
                "INSERT INTO nonce_cache (nonce, expires_at) VALUES (?, ?)",
                (nonce, now + ttl),
            )
            await db.commit()
        return True
