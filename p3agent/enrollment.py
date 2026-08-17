"""
P3 Agent Enrollment — one-time handshake with Controller.
"""

import base64
import json
from typing import Optional

import httpx


class AgentEnrollment:
    def __init__(self, client: httpx.AsyncClient):
        self._client = client

    async def enroll(self, token: str, public_key: bytes,
                      platform: str = "linux", version: str = "1.0.0") -> Optional[dict]:
        """
        Send enrollment request to Controller.
        Returns agent config if successful, None if failed.
        """
        try:
            resp = await self._client.post(
                "/api/v1/agents/enroll",
                json={
                    "enrollment_token": token,
                    "agent_name": "enrolling-agent",
                    "public_key": base64.b64encode(public_key).decode(),
                    "platform": platform,
                    "version": version,
                },
            )

            if resp.status_code == 200:
                return resp.json()
            else:
                print(f"Enrollment failed: {resp.status_code} {resp.text}")
                return None

        except Exception as e:
            print(f"Enrollment error: {e}")
            return None
