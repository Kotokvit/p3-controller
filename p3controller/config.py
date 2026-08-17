"""
P3 Config — load/save controller configuration.

Config file: ~/.config/p3-controller/config.toml
Master key:  ~/.config/p3-controller/master.key  (0600)
Database:    ~/.config/p3-controller/controller.db (0600)
"""

import os
import stat
import secrets
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib

import tomli_w

from cryptography.fernet import Fernet


DEFAULT_CONFIG_DIR = Path.home() / ".config" / "p3-controller"
DEFAULT_DB_PATH = DEFAULT_CONFIG_DIR / "controller.db"
DEFAULT_MASTER_KEY_PATH = DEFAULT_CONFIG_DIR / "master.key"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"

DEFAULT_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 8443,
    },
    "security": {
        "enrollment_ttl": 600,
        "request_clock_skew": 30,
        "max_command_timeout": 3600,
    },
    "sandbox": {
        "runtime": "docker",
        "default_profile": "sandbox",
    },
    "database": {
        "path": str(DEFAULT_DB_PATH),
    },
}


class P3Config:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.config_path = self.config_dir / "config.toml"
        self.db_path = self.config_dir / "controller.db"
        self.master_key_path = self.config_dir / "master.key"
        self._config: dict = {}
        self._master_key: Optional[bytes] = None

    def ensure_dir(self):
        """Create config directory with correct permissions."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.config_dir, stat.S_IRWXU)  # 0700

    def load(self) -> dict:
        """Load config from file, or create default."""
        self.ensure_dir()
        if self.config_path.exists():
            with open(self.config_path, "rb") as f:
                self._config = tomllib.load(f)
        else:
            self._config = DEFAULT_CONFIG.copy()
            self._config["database"]["path"] = str(self.db_path)
            self.save()
        return self._config

    def save(self):
        with open(self.config_path, "wb") as f:
            tomli_w.dump(self._config, f)
        os.chmod(self.config_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    @property
    def config(self) -> dict:
        if not self._config:
            self.load()
        return self._config

    def get(self, *keys, default=None):
        """Nested get: config.get('server', 'port') → 8443"""
        obj = self.config
        for k in keys:
            if isinstance(obj, dict) and k in obj:
                obj = obj[k]
            else:
                return default
        return obj

    # ── Master Key ─────────────────────────────────────────
    def get_master_key(self) -> bytes:
        """Get or create Fernet-compatible master key (32 url-safe-base64 bytes)."""
        if self._master_key:
            return self._master_key
        self.ensure_dir()
        if self.master_key_path.exists():
            with open(self.master_key_path, "rb") as f:
                key = f.read().strip()
            if len(key) == 44:  # Fernet key is 32 bytes base64 = 44 chars
                self._master_key = key
                return key
        # Generate new master key
        key = Fernet.generate_key()
        with open(self.master_key_path, "wb") as f:
            f.write(key)
        os.chmod(self.master_key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        self._master_key = key
        return key

    def set_master_key(self, key: bytes):
        """Set master key explicitly (for testing)."""
        self._master_key = key
