#!/bin/bash
# Run a software update after a short delay (web UI triggers this).
set -euo pipefail

REPO_DIR="${1:-/var/lib/hackertrap/repo}"
REPO_URL="${2:-https://github.com/marckranat/hackertrap}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sleep 2
exec >> /var/lib/hackertrap/update.log 2>&1
echo "==> Web update starting at $(date)"

REPO_DIR="$(bash "$SCRIPT_DIR/sync-repo.sh" "$REPO_URL" "$REPO_DIR")"
bash "$REPO_DIR/deploy/update.sh"
