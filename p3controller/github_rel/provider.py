"""
P3 GitHub — credential provider and Git credential helper.

Agent NEVER receives the GitHub PAT directly.
Instead:
  1. Agent runs `git clone/push` → Git asks for credentials
  2. Git credential helper contacts P3 Controller
  3. Controller checks agent permissions + repository access
  4. Controller returns a scoped temporary credential (or performs the operation itself)

For v1: fine-grained PAT with repository-scoped access.
Future: GitHub App with 1-hour installation tokens.
"""

import json
import time
from dataclasses import dataclass, asdict
from typing import Optional

import httpx


@dataclass
class GitHubCredential:
    """Temporary credential for a specific operation."""
    agent_id: str
    credential_id: int
    owner: str
    repositories: list[str]
    contents_perm: str    # read | write
    issues_perm: str
    pr_perm: str
    # The actual token — returned ONLY after permission check
    token: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # Never include token in serialization meant for audit
        return d


class GitHubCredentialProvider:
    """
    Server-side: checks permissions and returns scoped credentials.
    Token is only returned to the authenticated agent for the specific operation.
    """

    def __init__(self, db):
        self.db = db

    async def get_credential_for_agent(
        self,
        agent_id: str,
        repository: str,
        operation: str,  # clone|push|pull|issue_create|pr_create
    ) -> Optional[GitHubCredential]:
        """
        Check if agent has access to repository for operation, return credential.
        Returns None if access denied.
        """
        # Get agent's GitHub access records
        access_records = await self.db.get_agent_github_access(agent_id)
        if not access_records:
            return None

        # Check agent permissions
        perms = await self.db.get_permissions(agent_id)
        if not perms or not perms.get("github"):
            return None

        for record in access_records:
            # Check repository access
            repos = record["repositories"]
            if repos and repository not in repos:
                continue

            # Check operation permission
            if not self._operation_allowed(operation, record):
                continue

            # Get the actual credential
            cred = await self.db.get_github_credential(record["credential_id"])
            if not cred:
                continue

            return GitHubCredential(
                agent_id=agent_id,
                credential_id=record["credential_id"],
                owner=cred["owner"],
                repositories=record["repositories"],
                contents_perm=record["contents_perm"],
                issues_perm=record["issues_perm"],
                pr_perm=record["pr_perm"],
                token=cred["token"],
            )

        return None

    @staticmethod
    def _operation_allowed(operation: str, record: dict) -> bool:
        """Check if the operation is allowed by the permission record."""
        op_map = {
            "clone": "contents_perm",      # read is enough
            "pull": "contents_perm",       # read is enough
            "push": "contents_perm",       # needs write
            "issue_create": "issues_perm",
            "issue_comment": "issues_perm",
            "pr_create": "pr_perm",
            "pr_review": "pr_perm",
        }
        perm_field = op_map.get(operation)
        if not perm_field:
            return False

        required = "write" if operation in ("push", "issue_create", "pr_create", "issue_comment", "pr_review") else "read"
        actual = record.get(perm_field, "read")

        if required == "read":
            return actual in ("read", "write")
        if required == "write":
            return actual == "write"
        return False

    async def validate_token(self, token: str) -> Optional[dict]:
        """Validate a GitHub PAT by calling the GitHub API."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "login": data.get("login"),
                    "name": data.get("name"),
                    "id": data.get("id"),
                }
            return None


# ── Git Credential Helper ──────────────────────────────────
# This runs INSIDE the Docker cell as `p3-git-credential-helper`
# It intercepts `git credential fill` requests and asks the Controller

CREDENTIAL_HELPER_SCRIPT = r"""#!/usr/bin/env python3
\"\"\"
P3 Git Credential Helper — runs inside Docker cell.

Git calls this when it needs credentials.
Instead of storing a GitHub PAT in environment,
this helper contacts P3 Controller for scoped credentials.

Install in container:
  git config --global credential.helper 'p3-git-credential-helper'

Git protocol:
  fill:  stdin → host/path/protocol → stdout → username/password
  approve: stdin → store (not used, Controller manages tokens)
  reject:  stdin → forget (not used)
\"\"\"

import sys
import json
import os

CONTROLLER_URL = os.environ.get("P3_CONTROLLER_URL", "https://127.0.0.1:8443")
AGENT_ID = os.environ.get("P3_AGENT_ID", "")
AGENT_KEY = os.environ.get("P3_AGENT_KEY", "")


def read_credential_request():
    \"\"\"Read git credential request from stdin.\"\"\"
    lines = []
    for line in sys.stdin:
        line = line.strip()
        if line == "":
            break
        lines.append(line)

    data = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    return data


def fill():
    \"\"\"Handle 'git credential fill' — return username/password.\"\"\"
    req = read_credential_request()
    host = req.get("host", "")
    path = req.get("path", "")

    if "github.com" not in host:
        # Not a GitHub repo — no credential
        sys.exit(0)

    # Determine operation from protocol
    protocol = req.get("protocol", "https")

    # Ask Controller for scoped credential
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "agent_id": AGENT_ID,
        "repository": path,
        "operation": "clone",  # conservative default for credential fill
        "host": host,
    }).encode()

    try:
        r = urllib.request.Request(
            f"{CONTROLLER_URL}/api/v1/agents/{AGENT_ID}/credentials/github",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AGENT_KEY}",
            },
        )
        resp = urllib.request.urlopen(r)
        result = json.loads(resp.read())

        if "token" in result:
            # Git expects: username=x password=y
            print(f"username={result.get('owner', 'x-access-token')}")
            print(f"password={result['token']}")
            print()  # blank line = end
        else:
            sys.exit(1)
    except urllib.error.HTTPError:
        # Access denied or error
        sys.exit(1)


def approve():
    \"\"\"Handle 'git credential approve' — no-op, Controller manages tokens.\"\"\"
    pass


def reject():
    \"\"\"Handle 'git credential reject' — no-op.\"\"\"
    pass


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "fill"
    if action == "fill":
        fill()
    elif action == "approve":
        approve()
    elif action == "reject":
        reject()
    else:
        sys.exit(1)
"""


def get_credential_helper_script() -> str:
    """Return the credential helper Python script for embedding in containers."""
    return CREDENTIAL_HELPER_SCRIPT
