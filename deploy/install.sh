#!/bin/bash
# Install HackerTrap on Raspberry Pi OS (Bookworm, 64-bit).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

INSTALL_DIR="/opt/hackertrap"
DATA_DIR="/var/lib/hackertrap"
CONFIG_DIR="/etc/hackertrap"
VENV="$INSTALL_DIR/.venv"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Installing system packages"
apt-get update
apt-get install -y python3 python3-venv python3-pip iptables avahi-daemon rsync curl conntrack

# Optional: persist iptables across reboot (ExecStartPre also re-applies rules on start).
if ! dpkg -l iptables-persistent &>/dev/null; then
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent || true
fi

echo "==> Creating directories"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$CONFIG_DIR"

echo "==> Copying application"
rsync -a --exclude '.venv' --exclude '__pycache__' --exclude 'data' --exclude '.git' \
  "$REPO_DIR/" "$INSTALL_DIR/"

echo "==> Creating virtualenv"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -e "$INSTALL_DIR"

if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  echo "==> Creating default config"
  cat > "$CONFIG_DIR/config.yaml" <<EOF
device_id: $(openssl rand -hex 4)
setup_complete: false
data_dir: $DATA_DIR

honeypot:
  hostname: accountserver
  listen_host: 0.0.0.0
  ports:
    ftp: 21
    telnet: 23
    vnc: 5900

notifications:
  ntfy:
    enabled: false
    server: https://ntfy.sh
    topic: ""
    token: ""
  webhooks: []

web:
  host: 0.0.0.0
  port: 8080
  setup_token: $(openssl rand -base64 16 | tr -d '/+=' | head -c 22)

detector:
  log_source: auto
  log_path: /var/log/kern.log
  scan_threshold: 10
  scan_window_seconds: 60

system:
  repo_url: https://github.com/marckranat/hackertrap
  repo_path: /var/lib/hackertrap/repo
EOF
  chmod 600 "$CONFIG_DIR/config.yaml"
fi

echo "==> Installing systemd service"
cp "$REPO_DIR/deploy/systemd/hackertrap.service" /etc/systemd/system/
chmod +x "$REPO_DIR/deploy/iptables/setup.sh"
systemctl daemon-reload
systemctl enable hackertrap.service

echo "==> Configuring iptables logging"
"$REPO_DIR/deploy/iptables/setup.sh"
chmod +x "$REPO_DIR/deploy/update-web.sh" "$REPO_DIR/deploy/sync-repo.sh"

echo "==> Cloning update source to $DATA_DIR/repo"
bash "$INSTALL_DIR/deploy/sync-repo.sh" "https://github.com/marckranat/hackertrap" "$DATA_DIR/repo" >/dev/null
if COMMIT=$(git -C "$DATA_DIR/repo" log -1 --format="%h %s" 2>/dev/null); then
  echo "$COMMIT" > "$DATA_DIR/installed-commit"
fi

echo "==> Configuring mDNS hostname (hackertrap.local)"
if ! grep -q "hackertrap" /etc/avahi/services/hackertrap.service 2>/dev/null; then
  cp "$REPO_DIR/deploy/avahi/hackertrap.service" /etc/avahi/services/
  systemctl restart avahi-daemon
fi

echo "==> Starting HackerTrap"
systemctl restart hackertrap.service

IP=$(hostname -I | awk '{print $1}')
echo ""
echo "HackerTrap installed."
echo "  Web UI:  http://hackertrap.local:8080  (or http://${IP}:8080)"
echo "  Config:  $CONFIG_DIR/config.yaml"
echo ""
echo "Open the web UI to finish setup and configure notifications."
