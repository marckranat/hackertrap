#!/bin/bash
# Pull latest code and reinstall.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

INSTALL_DIR="/opt/hackertrap"
DATA_DIR="/var/lib/hackertrap"
VENV="$INSTALL_DIR/.venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="${HACKERTRAP_REPO_URL:-https://github.com/marckranat/hackertrap}"
STANDARD_REPO="$DATA_DIR/repo"
INSTALLED_COMMIT_FILE="$DATA_DIR/installed-commit"

# Use the checkout this script was invoked from, or the standard GitHub clone.
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ ! -d "$REPO_DIR/.git" ]]; then
  REPO_DIR="$(bash "$SCRIPT_DIR/sync-repo.sh" "$REPO_URL" "$STANDARD_REPO")"
else
  echo "==> Pulling latest in $REPO_DIR"
  git -C "$REPO_DIR" pull --ff-only
fi

if [[ "$REPO_DIR" != "$STANDARD_REPO" ]]; then
  echo "==> Refreshing standard repo at $STANDARD_REPO (for web updates)"
  REPO_DIR="$(bash "$SCRIPT_DIR/sync-repo.sh" "$REPO_URL" "$STANDARD_REPO")"
fi

echo "==> Syncing to $INSTALL_DIR"
rsync -a --exclude '.venv' --exclude '__pycache__' --exclude 'data' --exclude '.git' \
  "$REPO_DIR/" "$INSTALL_DIR/"

if COMMIT=$(git -C "$REPO_DIR" log -1 --format="%h %s" 2>/dev/null); then
  echo "$COMMIT" > "$INSTALLED_COMMIT_FILE"
fi

echo "==> Reinstalling Python package (includes web templates)"
"$VENV/bin/pip" install -e "$INSTALL_DIR"

if ! command -v curl >/dev/null 2>&1; then
  echo "==> Installing curl (used for health checks)"
  apt-get update
  apt-get install -y curl
fi

CONFIG="/etc/hackertrap/config.yaml"
if [[ -f "$CONFIG" ]] && grep -q '^    ssh: 22$' "$CONFIG" 2>/dev/null; then
  echo "==> Removing obsolete ssh:22 honeypot port from config (SSH probes use network logging)"
  sed -i '/^    ssh: 22$/d' "$CONFIG"
fi

if [[ -f "$CONFIG" ]]; then
  "$VENV/bin/python" - <<PY
from hackertrap.config import load_config, save_config
cfg = load_config()
cfg.system.repo_url = "$REPO_URL"
cfg.system.repo_path = "$STANDARD_REPO"
save_config(cfg)
PY
fi

chmod +x "$INSTALL_DIR/deploy/sync-repo.sh" "$INSTALL_DIR/deploy/update-web.sh" "$INSTALL_DIR/deploy/iptables/setup.sh" 2>/dev/null || true

echo "==> Updating systemd service"
cp "$INSTALL_DIR/deploy/systemd/hackertrap.service" /etc/systemd/system/
systemctl daemon-reload

echo "==> Applying iptables logging rules"
bash "$INSTALL_DIR/deploy/iptables/setup.sh"

echo "==> Restarting service"
systemctl restart hackertrap.service
sleep 3

if ! systemctl is-active --quiet hackertrap.service; then
  echo "Service failed to start — check: sudo journalctl -u hackertrap -n 40 --no-pager"
  exit 1
fi

IP=$(hostname -I | awk '{print $1}')
if command -v curl >/dev/null 2>&1 && curl -sf http://127.0.0.1:8080/health >/dev/null; then
  echo "OK — HackerTrap updated. Web UI: http://${IP}:8080"
elif python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=5)" 2>/dev/null; then
  echo "OK — HackerTrap updated. Web UI: http://${IP}:8080"
else
  echo "Service is running but HTTP check inconclusive."
  echo "  Try: http://${IP}:8080  or  http://$(hostname):8080"
  echo "  Logs: sudo journalctl -u hackertrap -n 40 --no-pager"
fi
