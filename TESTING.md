# Testing HackerTrap

How to verify bait services, scan detection, reboot alerts, and notifications from a **Mac or Linux** machine on the same network — no Windows or NAS hardware required.

Set your device address once (find it on the Pi with `hostname -I`, or use your `.local` hostname):

```bash
export TARGET=<your-device-ip>
# Example: export TARGET=10.0.0.42
```

All commands below use `$TARGET`. Nothing here is tied to a specific network or install.

---

## Prerequisites

On your Mac:

```bash
brew install nmap
```

`curl` and `nc` (netcat) are usually pre-installed.

### Automated smoke test

On the Pi (auto-detects LAN IP):

```bash
sudo bash /opt/hackertrap/deploy/smoke-test.sh
```

From another machine:

```bash
TARGET=<your-device-ip> bash deploy/smoke-test.sh
```

Override ports if needed: `TARGET=10.0.0.42 HTTP_PORT=80 ADMIN_PORT=8080 bash deploy/smoke-test.sh`

---

## 1. Admin UI (should always work)

```bash
curl -sf "http://${TARGET}:8080/health"
```

Expected: `{"status":"ok","version":"..."}`

The admin UI on **port 8080** is separate from the decoy web page on **port 80**.

---

## 2. Bait services (Tier 1 & 2)

Each probe should produce an alert on your phone and a row on the dashboard.

| Service | Test command | What “good” looks like |
|---------|--------------|------------------------|
| **FTP** | `nc -v $TARGET 21` | Banner with `220` and ProFTPD; optional `331 Anonymous` |
| **Telnet** | `nc -v $TARGET 23` | `login:` prompt |
| **VNC** | `nc -v $TARGET 5900` | `RFB 003.008` |
| **HTTP decoy** | `curl -v http://$TARGET/` | Fake sign-in page (not the HackerTrap dashboard) |
| **SMB** | `nc -v $TARGET 445` | Connection accepted; alert fires |
| **SNMP** | `nc -v -u $TARGET 161` | UDP probe alert |
| **UPnP/SSDP** | See below | UDP probe alert on port 1900 |

SMB fingerprint (no Windows needed):

```bash
nmap -p 445 --script smb-os-discovery "$TARGET"
```

SSDP M-SEARCH probe:

```bash
printf 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n' | nc -u -w 2 "$TARGET" 1900
```

---

## 3. iptables-logged probes (Tier 1)

These ports are **not** fake services — touches are logged and named in alerts.

```bash
nmap -p 22,139,3306,5432,6379,3389,27017 "$TARGET"
```

| Port | Alert name |
|------|------------|
| 22 | SSH probe (real sshd still works for you) |
| 139 | NetBIOS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 3389 | RDP |
| 27017 | MongoDB |

Rate limit: one alert per source IP + port per hour (avoids spam during broad scans).

---

## 4. Port scan detection

```bash
nmap -p 20-120 --min-rate 50 "$TARGET"
```

Expected: **one** port-scan alert when 10+ distinct ports are touched within 60 seconds.

Verify iptables logging is active (dashboard or):

```bash
sudo iptables -L HACKERTRAP -n | grep -i LOG
```

---

## 5. mDNS / network discovery

On Mac:

```bash
dns-sd -B _http._tcp local.
dns-sd -B _smb._tcp local.
```

You should see your persona name (e.g. **Accounting Server**), not “HackerTrap”.

On Linux:

```bash
avahi-browse -a -t
```

---

## 6. Reboot notification

**Should notify** (full reboot):

```bash
ssh <user>@$TARGET 'sudo reboot'
```

**Should NOT notify** (service restart only):

```bash
ssh <user>@$TARGET 'sudo systemctl restart hackertrap'
```

Toggle in **Settings → Notify when the device reboots**.

First boot after install establishes a baseline — no alert until the *next* reboot.

---

## 7. Test notifications

Use **Settings → Send test alert** (easiest).

---

## 8. Personas

During setup, pick **Accounting server**, **Backup NAS**, or **Print server**. Each sets:

- Hostname and mDNS advertisement
- Decoy HTTP login page content
- Full bait port layout

Custom hostname is still available for advanced users.

---

## 9. Automated tests (developers)

```bash
source .venv/bin/activate
pytest
```

Unit tests cover config/persona loading, iptables log parsing, probe rate limits, and reboot detection logic.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| No bait alerts | `sudo journalctl -u hackertrap -n 50` — port bind conflicts? |
| No scan alerts | Dashboard → Enable scan detection; or `sudo bash /opt/hackertrap/deploy/iptables/setup.sh` |
| HTTP decoy fails | Something else on port 80? `sudo ss -tlnp \| grep :80` |
| Too many alerts | You may be scanning your own trap — expected during testing |
| Reboot alert every restart | Should only fire on `boot_id` change — file `/var/lib/hackertrap/last_boot_id` |

---

## What not to test from the Pi itself

Probing `127.0.0.1` works for smoke tests, but scan-detection thresholds are best tested from **another machine** on the LAN so source IPs and timing match real attacker behaviour.
