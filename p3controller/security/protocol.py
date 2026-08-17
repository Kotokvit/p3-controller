"""
P3 Protocol — request signing, verification, replay protection.

Each authenticated request from Agent to Controller:
  1. Agent constructs canonical message: timestamp + nonce + method + path + body_hash
  2. Signs with Ed25519 private key
  3. Sends: Authorization: P3V1 agent=<id>, ts=<ts>, nonce=<n>, sig=<base64-sig>

Controller verifies:
  1. Finds agent's public key
  2. Checks timestamp is within clock skew tolerance
  3. Checks nonce is not replayed
  4. Reconstructs canonical message
  5. Verifies Ed25519 signature
"""

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .crypto import generate_nonce


AUTH_SCHEME = "P3V1"
CLOCK_SKEW_MAX = 30  # seconds


@dataclass
class SignedRequest:
    agent_id: str
    timestamp: float
    nonce: str
    signature: bytes
    method: str
    path: str
    body_hash: str  # SHA-256 hex of body


def canonical_message(timestamp: float, nonce: str, method: str, path: str, body_hash: str) -> bytes:
    """Construct canonical message for signing/verification."""
    return f"{timestamp}:{nonce}:{method}:{path}:{body_hash}".encode()


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign_request(
    agent_id: str,
    private_key,  # Ed25519PrivateKey
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: Optional[float] = None,
    nonce: Optional[str] = None,
) -> SignedRequest:
    """Sign an outgoing request (agent side)."""
    ts = timestamp or time.time()
    n = nonce or generate_nonce()
    bh = body_sha256(body)
    msg = canonical_message(ts, n, method, path, bh)
    sig = private_key.sign(msg)
    return SignedRequest(
        agent_id=agent_id,
        timestamp=ts,
        nonce=n,
        signature=sig,
        method=method,
        path=path,
        body_hash=bh,
    )


def verify_request(
    signed: SignedRequest,
    public_key: Ed25519PublicKey,
    clock_skew: int = CLOCK_SKEW_MAX,
) -> bool:
    """
    Verify an incoming request (controller side).
    Checks: signature validity + timestamp freshness.
    Nonce replay check is done separately via database.
    """
    # Check timestamp
    now = time.time()
    if abs(now - signed.timestamp) > clock_skew:
        return False  # stale or future-dated

    # Verify signature
    msg = canonical_message(
        signed.timestamp, signed.nonce, signed.method, signed.path, signed.body_hash
    )
    try:
        public_key.verify(signed.signature, msg)
        return True
    except InvalidSignature:
        return False


def format_auth_header(signed: SignedRequest) -> str:
    """Format Authorization header value."""
    sig_b64 = base64.b64encode(signed.signature).decode()
    return f"{AUTH_SCHEME} agent={signed.agent_id}, ts={signed.timestamp}, nonce={signed.nonce}, sig={sig_b64}"


def parse_auth_header(header: str) -> Optional[SignedRequest]:
    """Parse Authorization header. Returns None if invalid format."""
    if not header.startswith(f"{AUTH_SCHEME} "):
        return None
    parts = {}
    for token in header[len(AUTH_SCHEME) + 1:].split(", "):
        if "=" in token:
            k, v = token.split("=", 1)
            parts[k.strip()] = v.strip()
    try:
        return SignedRequest(
            agent_id=parts["agent"],
            timestamp=float(parts["ts"]),
            nonce=parts["nonce"],
            signature=base64.b64decode(parts["sig"]),
            method="",  # filled by middleware from actual request
            path="",
            body_hash="",
        )
    except (KeyError, ValueError):
        return None
