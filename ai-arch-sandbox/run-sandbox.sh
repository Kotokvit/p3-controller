#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="arch-ai-sandbox"

echo "==> Building Arch Linux AI Sandbox image..."
docker build -t "${IMAGE_NAME}" "${DIR}"

echo ""
echo "==> Starting interactive sandbox (root inside container)..."
echo "==> Note: changes inside /workspace will persist in ./workspace directory on host."
mkdir -p "${DIR}/workspace"

docker run -it --rm \
    --hostname arch-sandbox \
    -v "${DIR}/workspace:/workspace" \
    -w /root \
    "${IMAGE_NAME}" /bin/bash

