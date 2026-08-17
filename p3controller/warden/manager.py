"""
P3 Warden — Docker sandbox manager.

ALL AI commands execute inside Docker containers. NEVER on host.

Warden creates isolated cells with:
  - Drop-all capabilities + add only what's needed
  - No Docker socket mount
  - Read-only host filesystem
  - /workspace as the only writable mount
  - GPU passthrough (if permitted)
  - Network (if permitted, default off)
  - Resource limits (memory, CPU)
"""

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Optional

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from p3controller.security.permissions import SandboxConfig


@dataclass
class CellSpec:
    """Specification for a Docker cell."""
    agent_id: str
    command_id: str
    argv: list[str]       # NOT a shell string — structured argv only
    cwd: str = "/workspace"
    timeout: int = 3600
    config: SandboxConfig = None

    @staticmethod
    def from_dict(d: dict) -> "CellSpec":
        return CellSpec(
            agent_id=d["agent_id"],
            command_id=d["command_id"],
            argv=d["argv"],   # MUST be list, never string
            cwd=d.get("cwd", "/workspace"),
            timeout=d.get("timeout", 3600),
            config=d.get("config"),
        )


@dataclass
class CellResult:
    """Result from a cell execution."""
    command_id: str
    exit_code: int
    stdout: str
    stderr: str
    started_at: float
    finished_at: float
    truncated: bool = False


# ── Docker capabilities (SECURITY CRITICAL) ────────────────
# Default: drop ALL, add only what's absolutely needed
DEFAULT_CAPABILITIES_ADD = ["CHOWN", "SETUID", "SETGID", "FOWNER", "DAC_OVERRIDE"]
# NEVER add: SYS_ADMIN, NET_RAW, SYS_PTRACE, SYS_RESOURCE

BASE_DOCKER_IMAGE = "p3-cell:latest"
WORKSPACE_PATH = "/workspace"


class Warden:
    """Manages Docker cells for secure command execution."""

    def __init__(self, workspace_root: str = "/tmp/p3-workspace"):
        self.workspace_root = workspace_root
        self._client = None

    def _get_client(self):
        if not DOCKER_AVAILABLE:
            raise RuntimeError("Docker SDK not installed")
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _build_container_config(self, spec: CellSpec) -> dict:
        """Build Docker container create kwargs from CellSpec."""
        workspace_host = f"{self.workspace_root}/{spec.agent_id}"

        config = {
            "image": BASE_DOCKER_IMAGE,
            "command": spec.argv,  # list, NOT shell string
            "working_dir": spec.cwd,
            "detach": True,
            "name": f"p3-{spec.agent_id}-{spec.command_id}",
            # Security: drop all caps, add minimal
            "cap_drop": ["ALL"],
            "cap_add": DEFAULT_CAPABILITIES_ADD,
            # Security: no new privileges
            "security_opt": ["no-new-privileges"],
            # Security: read-only root filesystem
            "read_only": True,
            # Resource limits
            "mem_limit": "2g",
            "memswap_limit": "2g",
            "cpu_count": 2,
            # Workspace mount (tmpfs for writable area in read-only FS)
            "mounts": [
                {
                    "type": "bind",
                    "source": workspace_host,
                    "target": WORKSPACE_PATH,
                    "read_only": False,
                },
                {
                    "type": "tmpfs",
                    "target": "/tmp",
                    "tmpfs_options": {"size": "100m"},
                },
                {
                    "type": "tmpfs",
                    "target": "/run",
                    "tmpfs_options": {"size": "10m"},
                },
            ],
            "network_disabled": True,  # default: no network
            "auto_remove": False,      # we need to collect results
        }

        # Network access (if permitted by permissions)
        if spec.config and spec.config.network:
            config["network_disabled"] = False
            config["network_mode"] = "bridge"

        # GPU passthrough (if permitted)
        if spec.config and spec.config.gpu:
            config["device_requests"] = [
                docker.types.DeviceRequest(
                    driver="nvidia",
                    count=-1,  # all GPUs
                    capabilities=[["gpu", "compute", "utility"]],
                )
            ]

        # Extra mounts (trusted profile only, admin-configured)
        if spec.config and spec.config.extra_mounts:
            for mount in spec.config.extra_mounts:
                src, dst = mount.split(":", 1)
                config["mounts"].append({
                    "type": "bind",
                    "source": src,
                    "target": dst,
                    "read_only": True,  # extra mounts always read-only
                })

        return config

    async def execute(self, spec: CellSpec) -> CellResult:
        """
        Execute command in Docker cell. This is the ONLY execution path.
        NEVER subprocess.Popen on host. NEVER shell=True.
        """
        started = time.time()

        try:
            client = self._get_client()
            container_config = self._build_container_config(spec)

            # Ensure workspace directory exists
            import os
            workspace_host = f"{self.workspace_root}/{spec.agent_id}"
            os.makedirs(workspace_host, exist_ok=True)

            # Create and start container
            container = client.containers.create(**container_config)
            container.start()

            # Wait with timeout
            result = container.wait(timeout=spec.timeout)

            # Collect output
            stdout_raw = container.logs(stdout=True, stderr=False)
            stderr_raw = container.logs(stdout=False, stderr=True)

            stdout = stdout_raw.decode("utf-8", errors="replace")
            stderr = stderr_raw.decode("utf-8", errors="replace")

            # Truncate if too large
            MAX_OUTPUT = 1_000_000  # 1MB
            truncated = False
            if len(stdout) > MAX_OUTPUT:
                stdout = stdout[:MAX_OUTPUT]
                truncated = True
            if len(stderr) > MAX_OUTPUT:
                stderr = stderr[:MAX_OUTPUT]
                truncated = True

            exit_code = result.get("StatusCode", -1)

            # Clean up container
            try:
                container.remove(force=True)
            except Exception:
                pass

            return CellResult(
                command_id=spec.command_id,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                started_at=started,
                finished_at=time.time(),
                truncated=truncated,
            )

        except Exception as e:
            return CellResult(
                command_id=spec.command_id,
                exit_code=-1,
                stdout="",
                stderr=f"Warden error: {e}",
                started_at=started,
                finished_at=time.time(),
            )

    async def prepare_cell_image(self):
        """Build the base p3-cell Docker image if not present."""
        if not DOCKER_AVAILABLE:
            return False

        client = self._get_client()
        try:
            client.images.get(BASE_DOCKER_IMAGE)
            return True  # already exists
        except docker.errors.ImageNotFound:
            pass

        # Build minimal cell image
        dockerfile = """
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip nodejs npm gcc g++ git curl wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /tmp /run
WORKDIR /workspace

# Non-root user for extra safety
RUN useradd -m -s /bin/bash p3agent
USER p3agent

ENV HOME=/home/p3agent
"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            df_path = f"{tmpdir}/Dockerfile"
            with open(df_path, "w") as f:
                f.write(dockerfile)

            try:
                image, logs = client.images.build(
                    path=tmpdir,
                    tag=BASE_DOCKER_IMAGE,
                    rm=True,
                )
                return True
            except Exception as e:
                print(f"Failed to build cell image: {e}")
                return False

    async def list_active_cells(self) -> list[dict]:
        """List running P3 containers."""
        if not DOCKER_AVAILABLE:
            return []
        client = self._get_client()
        containers = client.containers.list(filters={"name": "p3-"})
        return [
            {
                "id": c.short_id,
                "name": c.name,
                "status": c.status,
                "image": str(c.image.tags[0]) if c.image.tags else str(c.image.id[:12]),
            }
            for c in containers
        ]

    async def kill_cell(self, container_name: str):
        """Force kill a cell."""
        if not DOCKER_AVAILABLE:
            return
        client = self._get_client()
        try:
            container = client.containers.get(container_name)
            container.kill()
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
