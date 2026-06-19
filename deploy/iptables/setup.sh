#!/bin/bash
# Add iptables rules to log inbound connection attempts for port scan detection.
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

CHAIN="HACKERTRAP"
IPT="${IPTABLES:-iptables}"

log() { echo "==> $*"; }

if ! command -v "$IPT" &>/dev/null; then
  echo "iptables not found"
  exit 1
fi

# Create chain if missing
if ! $IPT -L "$CHAIN" -n &>/dev/null; then
  log "Creating $CHAIN chain"
  $IPT -N "$CHAIN"
fi

# Jump from INPUT
if ! $IPT -C INPUT -j "$CHAIN" 2>/dev/null; then
  log "Linking INPUT -> $CHAIN"
  $IPT -I INPUT -j "$CHAIN"
fi

add_log_rule() {
  local proto="$1"
  shift
  if $IPT -C "$CHAIN" "$@" 2>/dev/null; then
    return 0
  fi
  if $IPT -A "$CHAIN" "$@" 2>/dev/null; then
    log "Added ${proto} LOG rule"
    return 0
  fi
  return 1
}

# Prefer conntrack NEW (quietest). Fall back to plain protocol logging.
if ! add_log_rule "tcp-conntrack" -m conntrack --ctstate NEW -p tcp -j LOG --log-prefix "HACKERTRAP: " --log-level 4; then
  log "conntrack unavailable for tcp — using simple LOG rule"
  add_log_rule "tcp" -p tcp -j LOG --log-prefix "HACKERTRAP: " --log-level 4 || true
fi

if ! add_log_rule "udp-conntrack" -m conntrack --ctstate NEW -p udp -j LOG --log-prefix "HACKERTRAP: " --log-level 4; then
  log "conntrack unavailable for udp — using simple LOG rule"
  add_log_rule "udp" -p udp -j LOG --log-prefix "HACKERTRAP: " --log-level 4 || true
fi

# Drop IGMP noise (same idea as original HoneyPi)
if ! $IPT -C INPUT -p igmp -j DROP 2>/dev/null; then
  $IPT -I INPUT -p igmp -j DROP 2>/dev/null || true
fi

# Persist if possible (optional — ExecStartPre re-applies rules on every boot anyway)
if command -v netfilter-persistent &>/dev/null; then
  netfilter-persistent save 2>/dev/null || true
else
  mkdir -p /etc/iptables
  $IPT-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

if $IPT -L "$CHAIN" -n 2>/dev/null | grep -qi log; then
  log "iptables HACKERTRAP logging rules OK"
  exit 0
fi

echo "Failed to install HACKERTRAP logging rules"
$IPT -L "$CHAIN" -n -v 2>&1 || true
exit 1
