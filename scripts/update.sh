#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== HAWK RADAR — Update ==="
echo "[1/3] Pulling latest changes…"
git pull --ff-only

echo "[2/3] Building & restarting containers…"
docker compose up --build -d

echo "[3/3] Done."
docker compose ps
