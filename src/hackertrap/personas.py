from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hackertrap.config import Config

AVAHI_SERVICE_PATH = Path("/etc/avahi/services/hackertrap.service")

DEFAULT_PORTS: dict[str, int] = {
    "ftp": 21,
    "telnet": 23,
    "vnc": 5900,
    "http": 80,
    "smb": 445,
    "snmp": 161,
    "ssdp": 1900,
}


@dataclass(frozen=True)
class Persona:
    id: str
    hostname: str
    display_name: str
    page_title: str
    headline: str
    subtitle: str


PERSONAS: dict[str, Persona] = {
    "accountserver": Persona(
        id="accountserver",
        hostname="accountserver",
        display_name="Accounting Server",
        page_title="Sign in — Internal Accounting",
        headline="Internal Accounting Portal",
        subtitle="Authorized personnel only. All access is logged.",
    ),
    "nas-backup": Persona(
        id="nas-backup",
        hostname="nas-backup",
        display_name="Backup NAS",
        page_title="Synology DiskStation — Sign in",
        headline="DiskStation Manager",
        subtitle="Backup appliance · RAID volume healthy",
    ),
    "print-spooler": Persona(
        id="print-spooler",
        hostname="print-spooler",
        display_name="Print Server",
        page_title="HP JetDirect — Device Status",
        headline="Enterprise Print Spooler",
        subtitle="Queue management · Internal use only",
    ),
}


def get_persona(persona_id: str) -> Persona | None:
    return PERSONAS.get(persona_id)


def list_persona_ids() -> tuple[str, ...]:
    return tuple(PERSONAS.keys())


def apply_persona(cfg: Config, persona_id: str) -> None:
    """Apply a preset persona to config (hostname, bait ports, persona id)."""
    persona = get_persona(persona_id)
    if persona is None:
        cfg.honeypot.persona = "custom"
        return

    cfg.honeypot.persona = persona.id
    cfg.honeypot.hostname = persona.hostname
    cfg.honeypot.ports = dict(DEFAULT_PORTS)


def build_decoy_page(persona_id: str, hostname: str) -> str:
    persona = get_persona(persona_id) or PERSONAS["accountserver"]
    host = hostname or persona.hostname
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{persona.page_title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #eef1f4; margin: 0; }}
    .wrap {{ max-width: 420px; margin: 8vh auto; background: #fff; padding: 2rem;
             border-radius: 6px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
    h1 {{ font-size: 1.25rem; margin: 0 0 .25rem; color: #1a1a1a; }}
    p.sub {{ color: #666; font-size: .9rem; margin: 0 0 1.5rem; }}
    label {{ display: block; font-size: .85rem; margin-bottom: .35rem; color: #444; }}
    input {{ width: 100%; padding: .55rem; margin-bottom: 1rem; box-sizing: border-box; }}
    button {{ width: 100%; padding: .65rem; background: #2563eb; color: #fff;
              border: 0; border-radius: 4px; cursor: pointer; }}
    .host {{ font-size: .75rem; color: #999; margin-top: 1rem; text-align: center; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{persona.headline}</h1>
    <p class="sub">{persona.subtitle}</p>
    <form action="#" method="post">
      <label for="user">Username</label>
      <input id="user" name="username" autocomplete="username" disabled placeholder="username">
      <label for="pass">Password</label>
      <input id="pass" name="password" type="password" autocomplete="current-password" disabled>
      <button type="button" disabled>Sign in</button>
    </form>
    <p class="host">{host}</p>
  </div>
</body>
</html>"""


def avahi_service_xml(cfg: Config) -> str:
    persona = get_persona(cfg.honeypot.persona) or PERSONAS["accountserver"]
    display = persona.display_name
    host = cfg.honeypot.hostname or persona.hostname
    http_port = cfg.honeypot.ports.get("http", 80)
    smb_port = cfg.honeypot.ports.get("smb", 445)

    return f"""<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">{display} on %h</name>
  <service>
    <type>_http._tcp</type>
    <port>{http_port}</port>
    <txt-record>path=/</txt-record>
    <txt-record>host={host}</txt-record>
  </service>
  <service>
    <type>_smb._tcp</type>
    <port>{smb_port}</port>
    <txt-record>workgroup=WORKGROUP</txt-record>
  </service>
  <service>
    <type>_device-info._tcp</type>
    <port>0</port>
    <txt-record>model={host}</txt-record>
  </service>
</service-group>
"""


def write_avahi_service(cfg: Config) -> bool:
    """Write Avahi mDNS service file. Returns True if file was updated."""
    if not cfg.setup_complete:
        return False

    xml = avahi_service_xml(cfg)
    AVAHI_SERVICE_PATH.parent.mkdir(parents=True, exist_ok=True)

    if AVAHI_SERVICE_PATH.is_file() and AVAHI_SERVICE_PATH.read_text(encoding="utf-8") == xml:
        return False

    AVAHI_SERVICE_PATH.write_text(xml, encoding="utf-8")
    return True
