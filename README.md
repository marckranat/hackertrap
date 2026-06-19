# HackerTrap

**A tripwire for your home or office network.**

Your router does a decent job keeping bad stuff off the internet from getting *in*. But once something is on your network — a stolen laptop, a dodgy guest device, someone who guessed the Wi‑Fi password — it can poke around for hours and you'd never know.

HackerTrap fixes that. It's a small always-on device that sits quietly on your network pretending to be ordinary infrastructure — an account server, a file manager, that kind of thing. When something starts snooping, **you get a notification on your phone.**

Plug it in. Set it up in your browser in about five minutes. Forget about it until it matters.

**[hackertraps.com](https://hackertraps.com)**

---

## What you need

### Minimum (it'll work)

| | |
|---|---|
| **Device** | Raspberry Pi 3B+ or newer |
| **Memory card** | 8 GB microSD |
| **Software** | Raspberry Pi OS Lite, 64-bit (Bookworm) — free download |
| **Your network** | Wi‑Fi or a network cable, with a normal home router that hands out addresses automatically |
| **Phone alerts** | Internet access on the device (for push notifications) |

### Recommended (best experience)

| | |
|---|---|
| **Device** | Raspberry Pi 4 or **Pi 5** |
| **Memory card** | 16 GB or larger |
| **Connection** | **Network cable (Ethernet)** — plug in and go, no Wi‑Fi fiddling |
| **Power** | Official Raspberry Pi power adapter |
| **Tip** | Use the Pi just for HackerTrap — don't run other stuff on it |

### About your network

You don't need to be a tech person for this. Here's what actually matters:

| | In plain English |
|---|---|
| **Automatic setup** | Your router needs to give the Pi an address on its own — the same way it does for your phone or printer. Almost every home router does this already. You don't need to configure anything special. |
| **Network cable** | Easiest option. Plug the cable from your router into the Pi, plug in power, open the setup page. Done. |
| **Wi‑Fi** | Works fine, but you'll need to connect the Pi to your Wi‑Fi first using the [Raspberry Pi Imager](https://www.raspberrypi.com/software/) app on your computer before running the installer. |
| **Internet** | Needed to send alerts to your phone. If your network blocks outbound traffic, alerts are still saved on the device — you just won't get a push notification. |
| **Guest Wi‑Fi** | Put HackerTrap on your **main** network (the one your computers and printers use), not the guest network. That's the one you want to watch. |
| **Opening ports** | Not needed. HackerTrap doesn't expose anything to the internet. It just listens quietly inside your network. |

---

## What you'll get alerted about

HackerTrap watches for the kind of snooping that happens *before* someone tries anything serious:

1. **Port scanning** — something systematically checking what's on your network
2. **FTP probes** (port 21) — something connecting to an old file-server port
3. **Telnet probes** (port 23) — a sign of something automated and unfriendly
4. **SSH probes** (port 22) — something looking for remote access *(logged via network monitoring; see below)*
5. **VNC probes** (port 5900) — something hunting for open desktops

If you get an alert, something on your network is looking for a weak spot. It might be harmless — a misconfigured app, a curious teenager, a new smart device doing something dumb. Or it might not be. Either way, **now you know.**

### How the trap works (ports open vs closed)

HackerTrap runs **fake services** on FTP, Telnet, and VNC. Those ports show as **open** to a scanner — an attacker gets a plausible banner back, and you get an alert when they connect.

**Port 22 (SSH)** is different: your Pi needs SSH for you to manage it, so we can't run a fake SSH server on the same port. SSH probes are still detected via network logging when something touches port 22.

**Port scans** (many ports quickly) are detected separately — that's the classic "someone mapping your network" behaviour.

False alarms are unlikely from normal home use. The bait ports (FTP, Telnet, VNC) are almost never touched legitimately. Port-scan alerts are the most likely source of noise if you run network audit tools yourself.

---

## How alerts reach your phone

**Recommended: [ntfy](https://ntfy.sh)** — free push notifications to iPhone or Android.

1. Install the [ntfy app](https://docs.ntfy.sh/subscribe/phone/) on your phone
2. Subscribe to a secret topic name (e.g. pick something random, not `alerts`)
3. Enter that topic in the HackerTrap setup page or **Settings**
4. Tap **Send test alert**

More options in the [ntfy documentation](https://docs.ntfy.sh/). You can also use the ntfy website in a browser, but most people want phone push.

**Also supported:**

- **Discord or Slack** webhooks — if you already use one of those

No email passwords. No complicated accounts.

---

## Setup

You'll need a Raspberry Pi with a fresh **Raspberry Pi OS Lite 64-bit (Bookworm)** install.

Log in to your Pi (SSH from your computer, or plug in a keyboard and monitor). Raspberry Pi OS Lite doesn't include everything out of the box, so start with:

```bash
sudo apt update
sudo apt install -y git curl
```

Then download and install HackerTrap:

```bash
git clone https://github.com/marckranat/hackertrap.git
cd hackertrap
chmod +x deploy/install.sh deploy/iptables/setup.sh
sudo bash deploy/install.sh
```

The installer pulls in the rest automatically — Python, iptables, and the other bits it needs to run.

### Open the web UI

Use the **hostname you chose** when flashing the SD card (Raspberry Pi Imager) or during setup — not necessarily "hackertrap":

```
http://YOUR-HOSTNAME.local:8080
```

Examples: `http://fileserver.local:8080`, `http://accountserver.local:8080`

If `.local` doesn't work, use the Pi's IP address instead (find it in your router, or run `hostname -I` on the Pi).

Follow the setup wizard: pick a bland device name, set an **admin password**, configure ntfy, and send a test alert.

---

## Settings and updates

After setup, open **Settings** from the dashboard to:

- Change notification topics (no need to redo setup or edit YAML)
- Set or change the admin password
- Change the device timezone
- **Check for updates & install** (pulls from GitHub and restarts — config and alerts are kept)

To update over SSH:

```bash
sudo bash /opt/hackertrap/deploy/update.sh
```

Or from a git clone: `git pull` first, then the same command.

Updates always pull from [github.com/marckranat/hackertrap](https://github.com/marckranat/hackertrap).

---

## Security

The web UI runs on port **8080 on your local network only** — it is not exposed to the internet by default.

**Set an admin password** during setup (or in Settings afterward). This stops others on your Wi‑Fi from opening your dashboard.

Additional tips:

- Use a **random ntfy topic** — treat it like a password
- Keep SSH enabled for management, but use a strong Pi login password
- HackerTrap is a LAN tool — don't port-forward 8080 on your router

HTTPS on the local network is optional for a home device; the admin password is the main protection.

---

## For developers

Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp config.example.yaml config.local.yaml
mkdir -p data
HACKERTRAP_DATA_DIR=./data hackertrap
```

Open http://127.0.0.1:8080/setup

Production config: `/etc/hackertrap/config.yaml`

---

## License

GPL-3.0 — evolved from the original [HoneyPi](https://github.com/marckranat/HoneyPi) project.
