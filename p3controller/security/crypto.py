"""
P3 Crypto — Ed25519 identity, Agent Keys, enrollment tokens.

Agent Key format:  p3k_<agent_id>_<32-byte-urlsafe-secret>
Enrollment token:  p3e_<32-byte-urlsafe-secret>

Keys are NEVER stored in plaintext — only SHA-256 hashes in DB.
"""

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# ── Constants ──────────────────────────────────────────────
AGENT_KEY_PREFIX = "p3k_"
ENROLL_TOKEN_PREFIX = "p3e_"
AGENT_ID_PREFIX = "ag_"
COMMAND_ID_PREFIX = "cmd_"
SECRET_BYTES = 32  # 256-bit secrets
ENROLLMENT_TTL_DEFAULT = 600  # 10 minutes


# ── Agent ID / Key ─────────────────────────────────────────
def generate_agent_id() -> str:
    """Generate agent ID: ag_<8-char-hex>"""
    return f"{AGENT_ID_PREFIX}{secrets.token_hex(4)}"


def generate_agent_key(agent_id: str) -> str:
    """Generate full Agent Key: p3k_<agent_id>:<32-byte-secret>
    Uses ':' separator because agent_id contains '_'."""
    secret = secrets.token_urlsafe(SECRET_BYTES)
    return f"{AGENT_KEY_PREFIX}{agent_id}:{secret}"


def parse_agent_key(key: str) -> tuple[str, str]:
    """Parse Agent Key → (agent_id, secret). Raises ValueError if invalid.
    Format: p3k_<agent_id>:<secret> — ':' separates agent_id from secret."""
    if not key.startswith(AGENT_KEY_PREFIX):
        raise ValueError(f"Invalid Agent Key: must start with {AGENT_KEY_PREFIX}")
    rest = key[len(AGENT_KEY_PREFIX):]
    if ":" not in rest:
        raise ValueError("Invalid Agent Key: missing ':' separator between agent_id and secret")
    agent_id, secret = rest.split(":", 1)
    if not agent_id.startswith(AGENT_ID_PREFIX):
        raise ValueError(f"Invalid Agent Key: agent_id must start with {AGENT_ID_PREFIX}")
    if len(secret) < 32:
        raise ValueError("Invalid Agent Key: secret too short (min 32 chars)")
    return agent_id, secret


def hash_secret(secret: str) -> str:
    """SHA-256 hash of a secret for DB storage. NEVER store plaintext."""
    return hashlib.sha256(secret.encode()).hexdigest()


# ── Enrollment Token ───────────────────────────────────────
@dataclass
class EnrollmentToken:
    token: str
    agent_id: str
    agent_name: str
    created_at: float
    expires_at: float
    used: bool = False

    @staticmethod
    def generate(agent_id: str, agent_name: str, ttl: int = ENROLLMENT_TTL_DEFAULT) -> "EnrollmentToken":
        now = time.time()
        return EnrollmentToken(
            token=f"{ENROLL_TOKEN_PREFIX}{secrets.token_urlsafe(SECRET_BYTES)}",
            agent_id=agent_id,
            agent_name=agent_name,
            created_at=now,
            expires_at=now + ttl,
        )

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.used and not self.is_expired


# ── Ed25519 Identity ───────────────────────────────────────
@dataclass
class AgentIdentity:
    """Ed25519 keypair for request signing. Private key stays on agent side."""
    agent_id: str
    private_key: Optional[Ed25519PrivateKey] = None
    public_key: Optional[Ed25519PublicKey] = None

    @staticmethod
    def generate(agent_id: str) -> "AgentIdentity":
        private = Ed25519PrivateKey.generate()
        return AgentIdentity(
            agent_id=agent_id,
            private_key=private,
            public_key=private.public_key(),
        )

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the private key."""
        if self.private_key is None:
            raise ValueError("No private key — this is a controller-side identity")
        return self.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature with the public key."""
        if self.public_key is None:
            raise ValueError("No public key")
        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def public_key_bytes(self) -> bytes:
        """Raw public key bytes for storage/transmission."""
        if self.public_key is None:
            raise ValueError("No public key")
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_key_bytes(self) -> bytes:
        """Raw private key bytes — ONLY for agent-side storage."""
        if self.private_key is None:
            raise ValueError("No private key")
        return self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @staticmethod
    def from_public_bytes(agent_id: str, pub_bytes: bytes) -> "AgentIdentity":
        """Reconstruct identity from stored public key (controller side)."""
        return AgentIdentity(
            agent_id=agent_id,
            public_key=Ed25519PublicKey.from_public_bytes(pub_bytes),
        )

    @staticmethod
    def from_private_bytes(agent_id: str, priv_bytes: bytes) -> "AgentIdentity":
        """Reconstruct identity from stored private key (agent side)."""
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return AgentIdentity(
            agent_id=agent_id,
            private_key=priv,
            public_key=priv.public_key(),
        )


# ── Command ID ─────────────────────────────────────────────
def generate_command_id() -> str:
    """Generate command ID: cmd_<8-char-hex>_<timestamp>"""
    return f"{COMMAND_ID_PREFIX}{secrets.token_hex(4)}_{int(time.time())}"


# ── Nonce ──────────────────────────────────────────────────
def generate_nonce() -> str:
    """Generate a 16-byte random nonce for replay protection."""
    return secrets.token_urlsafe(16)
