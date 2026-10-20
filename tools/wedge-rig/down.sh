#!/bin/bash
# Stop and remove the rig container (and optionally the image with --image).
set -euo pipefail
NAME="${RIG_NAME:-ce-wedge-rig}"
docker rm -f "$NAME" >/dev/null 2>&1 || true
if [[ "${1:-}" == "--image" ]]; then
    docker rmi "$NAME" >/dev/null 2>&1 || true
fi
echo "rig down"
