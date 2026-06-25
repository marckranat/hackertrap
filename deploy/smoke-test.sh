#!/bin/bash
# Quick smoke test for HackerTrap bait services and scan logging.
#
# Usage (on the Pi — auto-detects LAN IP):
#   sudo bash deploy/smoke-test.sh
#
# From another machine on the network:
#   TARGET=<device-ip> bash deploy/smoke-test.sh
#
# Override ports if your config uses non-standard values:
#   TARGET=10.0.0.50 HTTP_PORT=80 ADMIN_PORT=8080 bash deploy/smoke-test.sh
#
set -euo pipefail

if [[ -z "${TARGET:-}" ]]; then
  TARGET="$(hostname -I 2>/dev/null | awk '{print $1}')"
  TARGET="${TARGET:-127.0.0.1}"
  echo "==> TARGET not set — using ${TARGET} (set TARGET=<ip> to test a remote device)"
else
  echo "==> TARGET=${TARGET}"
fi

ADMIN_PORT="${ADMIN_PORT:-8080}"
HTTP_PORT="${HTTP_PORT:-80}"
FTP_PORT="${FTP_PORT:-21}"
TELNET_PORT="${TELNET_PORT:-23}"
VNC_PORT="${VNC_PORT:-5900}"
SMB_PORT="${SMB_PORT:-445}"
SSH_PORT="${SSH_PORT:-22}"

pass=0
fail=0

check() {
  local name="$1"
  shift
  if "$@"; then
    echo "OK   $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name"
    fail=$((fail + 1))
  fi
}

echo ""
echo "==> HackerTrap smoke test against ${TARGET}"
echo ""

check "Admin health endpoint" curl -sf "http://${TARGET}:${ADMIN_PORT}/health" >/dev/null

if command -v nc >/dev/null 2>&1; then
  check "FTP banner" bash -c "nc -w 2 ${TARGET} ${FTP_PORT} </dev/null | grep -qi '220'"
  check "Telnet banner" bash -c "nc -w 2 ${TARGET} ${TELNET_PORT} </dev/null | grep -qi 'login'"
  check "VNC banner" bash -c "nc -w 2 ${TARGET} ${VNC_PORT} </dev/null | grep -qi 'RFB'"
  check "HTTP decoy" bash -c "curl -sf --max-time 3 http://${TARGET}:${HTTP_PORT}/ | grep -qi 'sign in\\|login\\|username'"
  check "SMB port open" bash -c "nc -z -w 2 ${TARGET} ${SMB_PORT}"
  check "SSH reachable (real sshd)" bash -c "nc -z -w 2 ${TARGET} ${SSH_PORT}"
else
  echo "SKIP nc probes — install netcat (nc)"
fi

if command -v iptables >/dev/null 2>&1; then
  check "iptables HACKERTRAP chain" iptables -L HACKERTRAP -n 2>/dev/null | grep -qi log
else
  echo "SKIP iptables check (not available on this host)"
fi

echo ""
echo "==> Results: ${pass} passed, ${fail} failed"
if [[ $fail -gt 0 ]]; then
  exit 1
fi
