"""
P3 Permissions — capability-based model with profiles.

Three built-in profiles:
  - sandbox:    locked down, no GPU/network/GitHub
  - developer:  full sandbox + GPU + network + GitHub
  - trusted:    like developer but allows extra mounts

host.enabled is ALWAYS false in v1.
Agent can NEVER self-upgrade permissions.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import json


@dataclass
class Permissions:
    sandbox: bool = True
    gpu: bool = False
    network: bool = False
    host: bool = False      # ALWAYS False in v1
    github: bool = False
    workspace_rw: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Permissions":
        return Permissions(**{k: bool(v) for k, v in d.items() if k in Permissions.__dataclass_fields__})


@dataclass
class GitHubPermission:
    enabled: bool = True
    repositories: list[str] = field(default_factory=list)
    contents: str = "read"   # read | write
    issues: str = "read"
    pull_requests: str = "read"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SandboxConfig:
    """What the Docker cell provides."""
    runtime: str = "docker"
    root_inside: bool = True          # root inside container is fine
    workspace: str = "/workspace"
    workspace_mode: str = "rw"
    gpu: bool = False
    network: bool = False
    extra_mounts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Profiles ───────────────────────────────────────────────
PROFILES = {
    "sandbox": {
        "permissions": Permissions(sandbox=True, gpu=False, network=False, host=False, github=False),
        "sandbox_config": SandboxConfig(gpu=False, network=False),
        "description": "Minimal — isolated container, no external access",
    },
    "developer": {
        "permissions": Permissions(sandbox=True, gpu=True, network=True, host=False, github=True),
        "sandbox_config": SandboxConfig(gpu=True, network=True),
        "description": "Full sandbox + GPU + network + GitHub via broker",
    },
    "trusted": {
        "permissions": Permissions(sandbox=True, gpu=True, network=True, host=False, github=True),
        "sandbox_config": SandboxConfig(gpu=True, network=True),
        "description": "Like developer, allows extra mounts (configured by admin)",
    },
}


def get_profile(name: str) -> dict:
    if name not in PROFILES:
        raise ValueError(f"Unknown profile: {name}. Available: {list(PROFILES.keys())}")
    return PROFILES[name]


def validate_permission_change(agent_id: str, current: Permissions, requested: Permissions) -> Permissions:
    """
    Agent can NEVER request host=True.
    Agent can NEVER escalate beyond what Controller assigned.
    Only Controller admin can change permissions.
    """
    if requested.host:
        raise PermissionError(f"Agent {agent_id}: host access is NEVER allowed for remote agents in v1")

    # Agent cannot self-escalate: new permissions must be subset of current
    for attr in ("sandbox", "gpu", "network", "github", "workspace_rw"):
        if getattr(requested, attr) and not getattr(current, attr):
            raise PermissionError(
                f"Agent {agent_id}: cannot self-grant {attr} — only Controller admin can upgrade permissions"
            )

    return requested
