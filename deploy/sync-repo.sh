#!/bin/bash
# Clone or pull the HackerTrap source from GitHub.
# Status messages go to stderr; stdout is ONLY the repo path (for $(...) capture).
set -euo pipefail

REPO_URL="${1:-https://github.com/marckranat/hackertrap}"
REPO_DIR="${2:-/var/lib/hackertrap/repo}"

mkdir -p "$(dirname "$REPO_DIR")"

# Repo is managed by root (web updates); allow all users to read git metadata.
git config --system --add safe.directory "$REPO_DIR" 2>/dev/null || true

clone_repo() {
  echo "==> Cloning $REPO_URL to $REPO_DIR" >&2
  rm -rf "$REPO_DIR"
  git clone "$REPO_URL" "$REPO_DIR" >&2
}

if [[ -d "$REPO_DIR/.git" ]]; then
  echo "==> Pulling latest from $REPO_URL" >&2
  if ! git -C "$REPO_DIR" pull --ff-only >&2; then
    echo "==> History diverged — resetting to origin/main" >&2
    git -C "$REPO_DIR" fetch origin >&2
    git -C "$REPO_DIR" reset --hard origin/main >&2
  fi
  if [[ ! -f "$REPO_DIR/deploy/update.sh" ]]; then
    echo "==> Repo incomplete — re-cloning" >&2
    clone_repo
  fi
else
  clone_repo
fi

printf '%s\n' "$REPO_DIR"
