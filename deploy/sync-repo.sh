#!/bin/bash
# Clone or pull the HackerTrap source from GitHub.
set -euo pipefail

REPO_URL="${1:-https://github.com/marckranat/hackertrap}"
REPO_DIR="${2:-/var/lib/hackertrap/repo}"

mkdir -p "$(dirname "$REPO_DIR")"

# Repo is managed by root (web updates); allow all users to read git metadata.
git config --system --add safe.directory "$REPO_DIR" 2>/dev/null || true

if [[ -d "$REPO_DIR/.git" ]]; then
  echo "==> Pulling latest from $REPO_URL"
  git -C "$REPO_DIR" pull --ff-only
else
  echo "==> Cloning $REPO_URL to $REPO_DIR"
  rm -rf "$REPO_DIR"
  git clone "$REPO_URL" "$REPO_DIR"
fi

echo "$REPO_DIR"
