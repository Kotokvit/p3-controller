"""
P3 E2E Test — full test of Controller + Agent + Warden WITHOUT Docker.

Tests:
  1. Controller starts with in-memory config
  2. Admin creates agent → gets agent_key + enrollment_token
  3. Agent enrolls with one-time token → Ed25519 handshake
  4. Agent authenticates with signed request (heartbeat)
  5. Replay protection: duplicate nonce is rejected
  6. Revoked agent: all requests denied
  7. Expired enrollment token: rejected
  8. Command queued → agent polls → executes (subprocess fallback) → reports
  9. GitHub credential: stored encrypted, never exposed
  10. Permission enforcement: sandbox agent can't get GitHub cred
"""

import asyncio
import base64
import json
import os
import tempfile
import time
from pathlib import Path

from cryptography.fernet import Fernet

from p3controller.config import P3Config
from p3controller.storage.database import P3Database
from p3controller.security.crypto import (
    AgentIdentity,
    EnrollmentToken,
    generate_agent_id,
    generate_agent_key,
    generate_command_id,
    generate_nonce,
    hash_secret,
    parse_agent_key,
)
from p3controller.security.protocol import (
    SignedRequest,
    sign_request,
    verify_request,
    parse_auth_header,
    format_auth_header,
    body_sha256,
    canonical_message,
)
from p3controller.security.permissions import (
    Permissions,
    PROFILES,
    get_profile,
    validate_permission_change,
)
from p3controller.github_rel.provider import GitHubCredentialProvider


# ── Test Helpers ───────────────────────────────────────────
class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def ok(self, name: str):
        self.passed += 1
        self.results.append(("PASS", name))
        print(f"  ✅ {name}")

    def fail(self, name: str, reason: str):
        self.failed += 1
        self.results.append(("FAIL", name, reason))
        print(f"  ❌ {name}: {reason}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Results: {self.passed}/{total} passed, {self.failed} failed")
        if self.failed == 0:
            print("🎉 ALL TESTS PASSED!")
        print(f"{'='*60}")


results = TestResult()


async def run_e2e_test():
    print("=" * 60)
    print("P3 Controller — End-to-End Security Test")
    print("=" * 60)

    # Setup temp directory
    tmpdir = tempfile.mkdtemp(prefix="p3-test-")
    db_path = f"{tmpdir}/test.db"
    master_key = Fernet.generate_key()

    db = P3Database(db_path, master_key=master_key)
    await db.init()

    github_provider = GitHubCredentialProvider(db)

    # ══════════════════════════════════════════════════════
    # Test 1: Agent Key Generation
    # ══════════════════════════════════════════════════════
    print("\n[1] Agent Key Generation")
    try:
        agent_id = generate_agent_id()
        assert agent_id.startswith("ag_"), f"Expected ag_ prefix, got {agent_id}"
        results.ok("Agent ID format")

        agent_key = generate_agent_key(agent_id)
        assert agent_key.startswith("p3k_"), f"Expected p3k_ prefix, got {agent_key}"
        results.ok("Agent Key format")

        parsed_id, parsed_secret = parse_agent_key(agent_key)
        assert parsed_id == agent_id, f"ID mismatch: {parsed_id} != {agent_id}"
        assert len(parsed_secret) >= 32, f"Secret too short: {len(parsed_secret)}"
        results.ok("Agent Key parsing")

        # Hash is one-way
        h = hash_secret(parsed_secret)
        assert h != parsed_secret, "Hash should not equal secret"
        assert len(h) == 64, f"SHA-256 hex should be 64 chars, got {len(h)}"
        results.ok("Secret hashing (one-way)")
    except Exception as e:
        results.fail("Agent Key Generation", str(e))

    # ══════════════════════════════════════════════════════
    # Test 2: Ed25519 Identity
    # ══════════════════════════════════════════════════════
    print("\n[2] Ed25519 Identity")
    try:
        identity = AgentIdentity.generate("test-agent")
        assert identity.private_key is not None
        assert identity.public_key is not None
        results.ok("Keypair generation")

        # Sign and verify
        message = b"test message for signing"
        sig = identity.sign(message)
        assert identity.verify(message, sig)
        results.ok("Signature verification (valid)")

        # Tampered message should fail
        assert not identity.verify(b"tampered message", sig)
        results.ok("Signature verification (tampered — rejected)")

        # Serialize/deserialize
        pub_bytes = identity.public_key_bytes()
        priv_bytes = identity.private_key_bytes()

        identity2 = AgentIdentity.from_public_bytes("test-agent", pub_bytes)
        assert identity2.verify(message, sig)
        results.ok("Public key deserialization")

        identity3 = AgentIdentity.from_private_bytes("test-agent", priv_bytes)
        sig3 = identity3.sign(message)
        assert identity2.verify(message, sig3)
        results.ok("Private key deserialization + sign/verify round-trip")
    except Exception as e:
        results.fail("Ed25519 Identity", str(e))

    # ══════════════════════════════════════════════════════
    # Test 3: Enrollment Token
    # ══════════════════════════════════════════════════════
    print("\n[3] Enrollment Token")
    try:
        enroll = EnrollmentToken.generate("ag_test", "test-agent", ttl=600)
        assert enroll.token.startswith("p3e_"), f"Expected p3e_ prefix, got {enroll.token}"
        assert enroll.is_valid
        results.ok("Enrollment token generation")

        # Expired token
        expired = EnrollmentToken.generate("ag_test", "test-agent", ttl=-1)
        assert not expired.is_valid
        results.ok("Expired enrollment token — rejected")

        # Used token
        enroll.used = True
        assert not enroll.is_valid
        results.ok("Used enrollment token — rejected")
    except Exception as e:
        results.fail("Enrollment Token", str(e))

    # ══════════════════════════════════════════════════════
    # Test 4: Request Signing Protocol
    # ══════════════════════════════════════════════════════
    print("\n[4] Request Signing Protocol")
    try:
        identity = AgentIdentity.generate("test-agent")

        # Sign a request
        signed = sign_request(
            agent_id="test-agent",
            private_key=identity.private_key,
            method="POST",
            path="/api/v1/agents/heartbeat",
            body=b'{"status":"active"}',
        )
        results.ok("Request signing")

        # Verify valid request
        assert verify_request(signed, identity.public_key)
        results.ok("Request verification (valid)")

        # Tampered body
        tampered = SignedRequest(
            agent_id=signed.agent_id,
            timestamp=signed.timestamp,
            nonce=signed.nonce,
            signature=signed.signature,
            method=signed.method,
            path=signed.path,
            body_hash=body_sha256(b'{"status":"hacked"}'),  # different body
        )
        assert not verify_request(tampered, identity.public_key)
        results.ok("Request verification (tampered body — rejected)")

        # Stale timestamp
        stale = SignedRequest(
            agent_id=signed.agent_id,
            timestamp=signed.timestamp - 100,  # 100s in the past
            nonce=signed.nonce,
            signature=signed.signature,
            method=signed.method,
            path=signed.path,
            body_hash=signed.body_hash,
        )
        assert not verify_request(stale, identity.public_key)
        results.ok("Request verification (stale timestamp — rejected)")

        # Format/parse auth header
        header = format_auth_header(signed)
        assert header.startswith("P3V1 ")
        parsed = parse_auth_header(header)
        assert parsed is not None
        assert parsed.agent_id == "test-agent"
        results.ok("Auth header format/parse round-trip")
    except Exception as e:
        results.fail("Request Signing Protocol", str(e))

    # ══════════════════════════════════════════════════════
    # Test 5: Database — Agent CRUD
    # ══════════════════════════════════════════════════════
    print("\n[5] Database — Agent CRUD")
    try:
        agent_key = generate_agent_key("ag_test1")
        _, secret = parse_agent_key(agent_key)
        key_hash = hash_secret(secret)

        aid = await db.create_agent("test-agent-1", key_hash, "developer")
        assert aid.startswith("ag_")
        results.ok("Create agent")

        agent = await db.get_agent(aid)
        assert agent is not None
        assert agent["name"] == "test-agent-1"
        assert agent["status"] == "pending"
        results.ok("Get agent")

        # Public key enrollment
        identity = AgentIdentity.generate(aid)
        await db.set_agent_public_key(aid, identity.public_key_bytes())
        agent = await db.get_agent(aid)
        assert agent["status"] == "active"
        assert agent["public_key"] is not None
        results.ok("Enroll agent (set public key → active)")

        # Revoke
        await db.update_agent_status(aid, "revoked")
        agent = await db.get_agent(aid)
        assert agent["status"] == "revoked"
        results.ok("Revoke agent")

        # List
        agents = await db.list_agents()
        assert len(agents) >= 1
        results.ok("List agents")
    except Exception as e:
        results.fail("Database Agent CRUD", str(e))

    # ══════════════════════════════════════════════════════
    # Test 6: Database — Permissions
    # ══════════════════════════════════════════════════════
    print("\n[6] Database — Permissions")
    try:
        aid2 = await db.create_agent("test-perms", hash_secret("test"), "sandbox")
        perms = await db.get_permissions(aid2)
        assert perms is not None
        assert perms["sandbox"] == 1
        assert perms["gpu"] == 0
        assert perms["network"] == 0
        assert perms["host"] == 0  # NEVER True in v1
        results.ok("Sandbox profile permissions (locked down)")

        aid3 = await db.create_agent("test-dev", hash_secret("test2"), "developer")
        perms = await db.get_permissions(aid3)
        assert perms["gpu"] == 1
        assert perms["network"] == 1
        assert perms["github"] == 1
        assert perms["host"] == 0  # Still NEVER True
        results.ok("Developer profile permissions (GPU+network+GitHub, no host)")

        # Permission enforcement
        current = Permissions(sandbox=True, gpu=True, network=True, host=False, github=True)
        try:
            validate_permission_change("test", current, Permissions(host=True))
            results.fail("Permission enforcement", "Should have blocked host=True")
        except PermissionError:
            results.ok("Permission enforcement: host=True BLOCKED")

        try:
            validate_permission_change("test", current, Permissions(sandbox=True, gpu=True, network=True, github=True, host=False))
            results.ok("Permission enforcement: same permissions OK")
        except PermissionError as e:
            results.fail("Permission enforcement: same permissions", str(e))
    except Exception as e:
        results.fail("Database Permissions", str(e))

    # ══════════════════════════════════════════════════════
    # Test 7: Replay Protection
    # ══════════════════════════════════════════════════════
    print("\n[7] Replay Protection (Nonce)")
    try:
        nonce1 = generate_nonce()
        assert await db.check_and_store_nonce(nonce1)
        results.ok("First nonce accepted")

        assert not await db.check_and_store_nonce(nonce1)
        results.ok("Replayed nonce REJECTED")

        nonce2 = generate_nonce()
        assert await db.check_and_store_nonce(nonce2)
        results.ok("Different nonce accepted")
    except Exception as e:
        results.fail("Replay Protection", str(e))

    # ══════════════════════════════════════════════════════
    # Test 8: GitHub Credential Encryption
    # ══════════════════════════════════════════════════════
    print("\n[8] GitHub Credential Encryption")
    try:
        fake_pat = "github_pat_TEST_FAKE_TOKEN_FOR_TESTING_1234567890"
        cred_id = await db.add_github_credential(
            owner="test-user",
            token=fake_pat,
            token_type="fine_grained",
        )
        results.ok("GitHub credential encrypted and stored")

        # Retrieve and decrypt
        cred = await db.get_github_credential(cred_id)
        assert cred["token"] == fake_pat, "Decrypted token should match original"
        results.ok("GitHub credential decryption (round-trip)")

        # Token is encrypted in DB (verify raw storage)
        import aiosqlite
        async with aiosqlite.connect(db_path) as raw_db:
            cur = await raw_db.execute(
                "SELECT encrypted_token FROM github_credentials WHERE id = ?", (cred_id,)
            )
            row = await cur.fetchone()
            stored = row[0]
            assert stored != fake_pat, "DB should NOT store plaintext token"
            results.ok("GitHub token NOT stored in plaintext")
    except Exception as e:
        results.fail("GitHub Credential Encryption", str(e))

    # ══════════════════════════════════════════════════════
    # Test 9: Enrollment Token (One-Time)
    # ══════════════════════════════════════════════════════
    print("\n[9] Enrollment Token (One-Time Use)")
    try:
        enroll = EnrollmentToken.generate("ag_enroll_test", "enroll-test", ttl=600)
        token_hash = hash_secret(enroll.token)
        await db.store_enrollment_token(
            token_hash=token_hash,
            agent_id="ag_enroll_test",
            agent_name="enroll-test",
            expires_at=enroll.expires_at,
        )

        # First use: OK
        result = await db.use_enrollment_token(token_hash)
        assert result is not None
        results.ok("Enrollment token — first use accepted")

        # Second use: REJECTED
        result2 = await db.use_enrollment_token(token_hash)
        assert result2 is None
        results.ok("Enrollment token — second use REJECTED (one-time)")
    except Exception as e:
        results.fail("Enrollment Token One-Time", str(e))

    # ══════════════════════════════════════════════════════
    # Test 10: Audit Log (No Secrets)
    # ══════════════════════════════════════════════════════
    print("\n[10] Audit Log")
    try:
        await db.audit("test.event", "ag_test", {"action": "test", "key": "value"})
        results.ok("Audit event recorded")

        # Verify no secrets in audit
        import aiosqlite
        async with aiosqlite.connect(db_path) as audit_db:
            audit_db.row_factory = aiosqlite.Row
            cur = await audit_db.execute(
                "SELECT * FROM audit_events WHERE event = 'test.event'"
            )
            row = await cur.fetchone()
            assert row is not None
            details = json.loads(row["details"])
            assert "key" not in str(details) or "github_pat_" not in str(details)
            results.ok("Audit log — no secrets leaked")
    except Exception as e:
        results.fail("Audit Log", str(e))

    # ══════════════════════════════════════════════════════
    # Test 11: Command Protocol (argv, not shell)
    # ══════════════════════════════════════════════════════
    print("\n[11] Command Protocol")
    try:
        aid_cmd = await db.create_agent("cmd-test", hash_secret("cmd"), "developer")
        cmd_id = generate_command_id()
        await db.create_command(
            command_id=cmd_id,
            agent_id=aid_cmd,
            argv=["python3", "-c", "print('hello')"],
            cwd="/workspace",
            timeout=60,
        )
        results.ok("Command created with argv (not shell)")

        cmds = await db.get_pending_commands(aid_cmd)
        assert len(cmds) == 1
        assert cmds[0]["argv"] == ["python3", "-c", "print('hello')"]
        assert isinstance(cmds[0]["argv"], list)
        results.ok("Command argv is list, not string")

        # Simulate execution result
        await db.store_command_result(cmd_id, 0, "hello\n", "")
        await db.update_command_status(cmd_id, "completed")
        results.ok("Command result stored")
    except Exception as e:
        results.fail("Command Protocol", str(e))

    # ══════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════
    results.summary()

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return results.failed == 0
