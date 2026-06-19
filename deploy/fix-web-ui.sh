#!/bin/bash
# Quick fix if HackerTrap web UI won't load (often port 22 conflict with SSH).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

CONFIG="/etc/hackertrap/config.yaml"

if [[ ! -f "$CONFIG" ]]; then
  echo "No config at $CONFIG — run deploy/install.sh first."
  exit 1
fi

# Remove fake SSH on port 22 (sshd already owns that port).
sed -i '/^    ssh: 22$/d' "$CONFIG"

systemctl restart hackertrap.service
sleep 3

if ! systemctl is-active --quiet hackertrap.service; then
  echo "Service failed to start. Check: sudo journalctl -u hackertrap -n 40 --no-pager"
  exit 1
fi

IP=$(hostname -I | awk '{print $1}')
if command -v curl >/dev/null 2>&1 && curl -sf http://127.0.0.1:8080/health >/dev/null; then
  echo "OK — web UI is up at http://${IP}:8080"
elif python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=5)" 2>/dev/null; then
  echo "OK — web UI is up at http://${IP}:8080"
else
  echo "Service running — open http://${IP}:8080 in your browser"
fi
