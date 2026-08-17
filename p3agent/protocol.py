"""
P3 Agent Protocol — Ed25519-signed authenticated requests.
"""

import json
import time
from typing import Optional

import httpx

from p3controller.security.crypto import generate_nonce
from p3controller.security.protocol import sign_request, body_sha256


class AgentProtocol:
    """Handles authenticated communication with Controller."""

    def __init__(self, agent_id: str, private_key, client: httpx.AsyncClient):
        self.agent_id = agent_id
        self.private_key = private_key
        self._client = client

    def _sign_and_headers(self, method: str, path: str, body: bytes = b"") -> dict:
        """Create signed request headers."""
        signed = sign_request(
            agent_id=self.agent_id,
            private_key=self.private_key,
            method=method,
            path=path,
            body=body,
        )

        from p3controller.security.protocol import format_auth_header
        return {
            "Authorization": format_auth_header(signed),
            "Content-Type": "application/json",
        }

    async def signed_get(self, path: str) -> dict:
        body = b""
        headers = self._sign_and_headers("GET", path, body)
        resp = await self._client.get(path, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def signed_post(self, path: str, data: dict) -> dict:
        body = json.dumps(data).encode()
        headers = self._sign_and_headers("POST", path, body)
        resp = await self._client.post(path, content=body, headers=headers)
        resp.raise_for_status()
        return resp.json()
