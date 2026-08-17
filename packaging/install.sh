#!/bin/bash
# P3 Controller — Install Script
set -e

echo "========================================="
echo "  P3 Controller v1 — Installer"
echo "========================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3.11+ required"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python: $PYTHON_VERSION"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "WARNING: Docker not found — Warden/sandbox will not work"
    echo "  Install Docker: https://docs.docker.com/get-docker/"
else
    echo "Docker: $(docker --version)"
fi

# Install Python dependencies
echo ""
echo "Installing Python packages..."
python3 -m pip install --user fastapi uvicorn cryptography aiosqlite httpx typer pydantic docker tomli_w tomli 2>&1 | tail -3

# Install P3 Controller
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
python3 -m pip install --user -e . 2>&1 | tail -3

# Create config directory
CONFIG_DIR="$HOME/.config/p3-controller"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Generate master key if not exists
if [ ! -f "$CONFIG_DIR/master.key" ]; then
    python3 -c "from cryptography.fernet import Fernet; open('$CONFIG_DIR/master.key', 'wb').write(Fernet.generate_key())"
    chmod 600 "$CONFIG_DIR/master.key"
    echo "Master key generated: $CONFIG_DIR/master.key"
else
    echo "Master key exists: $CONFIG_DIR/master.key"
fi

echo ""
echo "========================================="
echo "  Installation complete!"
echo ""
echo "  Start controller:  p3 server"
echo "  Add GitHub PAT:    p3 github add"
echo "  Create agent:      p3 agent create <name>"
echo ""
echo "  On remote machine:"
echo "    p3-agent enroll <token>"
echo "    p3-agent run"
echo "========================================="
