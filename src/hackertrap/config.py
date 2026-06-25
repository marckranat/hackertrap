from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATHS = (
    Path("/etc/hackertrap/config.yaml"),
    Path("config.local.yaml"),
    Path("config.yaml"),
)

DEFAULT_DATA_DIR = Path(os.environ.get("HACKERTRAP_DATA_DIR", "/var/lib/hackertrap"))

from hackertrap.personas import DEFAULT_PORTS

DEFAULT_HOSTNAME = "accountserver"
DEFAULT_PERSONA = "accountserver"
DEFAULT_REPO_URL = "https://github.com/marckranat/hackertrap"
DEFAULT_REPO_PATH = "/var/lib/hackertrap/repo"


def normalize_ntfy_topic(raw: str) -> str:
    """Accept a topic name or full ntfy URL — return just the topic."""
    topic = raw.strip()
    if not topic:
        return ""

    for prefix in ("https://", "http://"):
        if topic.startswith(prefix):
            topic = topic[len(prefix) :]
            break

    if topic.startswith("ntfy.sh/"):
        topic = topic[len("ntfy.sh/") :]

    topic = topic.split("?")[0].strip("/")
    if "/" in topic:
        topic = topic.rsplit("/", 1)[-1]

    return topic


def sanitize_honeypot_ports(ports: dict[str, int]) -> dict[str, int]:
    """Merge with defaults and drop ssh:22 — real sshd owns that port."""
    merged = dict(DEFAULT_PORTS)
    merged.update(ports)
    merged.pop("ssh", None)
    return merged


@dataclass
class NtfyConfig:
    enabled: bool = False
    server: str = "https://ntfy.sh"
    topic: str = ""
    token: str = ""


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""
    name: str = "webhook"


@dataclass
class NotificationsConfig:
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)
    webhooks: list[WebhookConfig] = field(default_factory=list)
    notify_on_reboot: bool = True


@dataclass
class HoneypotConfig:
    persona: str = DEFAULT_PERSONA
    hostname: str = DEFAULT_HOSTNAME
    listen_host: str = "0.0.0.0"
    ports: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_PORTS))


@dataclass
class WebConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    setup_token: str = ""
    admin_password_hash: str = ""
    session_secret: str = ""


@dataclass
class DetectorConfig:
    log_source: str = "auto"  # auto | journal | file
    log_path: str = "/var/log/kern.log"
    scan_threshold: int = 10  # ports touched within window
    scan_window_seconds: int = 60


@dataclass
class SystemConfig:
    repo_url: str = DEFAULT_REPO_URL
    repo_path: str = DEFAULT_REPO_PATH


@dataclass
class Config:
    device_id: str = ""
    setup_complete: bool = False
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    web: WebConfig = field(default_factory=WebConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    system: SystemConfig = field(default_factory=SystemConfig)
    data_dir: Path = field(default_factory=lambda: DEFAULT_DATA_DIR)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "alerts.db"

    @property
    def config_path(self) -> Path | None:
        return getattr(self, "_config_path", None)


def _parse_notifications(raw: dict[str, Any]) -> NotificationsConfig:
    ntfy_raw = raw.get("ntfy", {})
    webhooks_raw = raw.get("webhooks", [])
    return NotificationsConfig(
        ntfy=NtfyConfig(
            enabled=bool(ntfy_raw.get("enabled")),
            server=str(ntfy_raw.get("server", "https://ntfy.sh")),
            topic=str(ntfy_raw.get("topic", "")),
            token=str(ntfy_raw.get("token", "")),
        ),
        webhooks=[
            WebhookConfig(
                enabled=bool(w.get("enabled", True)),
                url=str(w.get("url", "")),
                name=str(w.get("name", "webhook")),
            )
            for w in webhooks_raw
        ],
        notify_on_reboot=bool(raw.get("notify_on_reboot", True)),
    )


def _as_dict(value: Any) -> dict[str, Any]:
    """YAML `null` sections become None — treat as empty dict."""
    return value if isinstance(value, dict) else {}


def load_config(path: Path | None = None) -> Config:
    config_path = path
    if config_path is None:
        env_data = os.environ.get("HACKERTRAP_DATA_DIR")
        extra_paths: tuple[Path, ...] = ()
        if env_data:
            extra_paths = (Path(env_data) / "config.yaml",)
        for candidate in (*DEFAULT_CONFIG_PATHS, *extra_paths):
            if candidate.exists():
                config_path = candidate
                break

    if config_path is None or not config_path.exists():
        cfg = Config()
        cfg.device_id = secrets.token_hex(4)
        cfg.web.setup_token = secrets.token_urlsafe(16)
        cfg._config_path = None
        return cfg

    with config_path.open() as f:
        raw = yaml.safe_load(f) or {}

    honeypot_raw = _as_dict(raw.get("honeypot"))
    web_raw = _as_dict(raw.get("web"))
    detector_raw = _as_dict(raw.get("detector"))
    system_raw = _as_dict(raw.get("system"))
    data_dir = Path(raw.get("data_dir", DEFAULT_DATA_DIR))

    cfg = Config(
        device_id=str(raw.get("device_id", secrets.token_hex(4))),
        setup_complete=bool(raw.get("setup_complete", False)),
        honeypot=HoneypotConfig(
            persona=str(honeypot_raw.get("persona", DEFAULT_PERSONA)),
            hostname=str(honeypot_raw.get("hostname", DEFAULT_HOSTNAME)),
            listen_host=str(honeypot_raw.get("listen_host", "0.0.0.0")),
            ports=sanitize_honeypot_ports(
                dict(honeypot_raw.get("ports") or DEFAULT_PORTS)
            ),
        ),
        notifications=_parse_notifications(_as_dict(raw.get("notifications"))),
        web=WebConfig(
            host=str(web_raw.get("host", "0.0.0.0")),
            port=int(web_raw.get("port", 8080)),
            setup_token=str(web_raw.get("setup_token", secrets.token_urlsafe(16))),
            admin_password_hash=str(web_raw.get("admin_password_hash", "")),
            session_secret=str(web_raw.get("session_secret", "")),
        ),
        detector=DetectorConfig(
            log_source=str(detector_raw.get("log_source", "auto")),
            log_path=str(detector_raw.get("log_path", "/var/log/kern.log")),
            scan_threshold=int(detector_raw.get("scan_threshold", 10)),
            scan_window_seconds=int(detector_raw.get("scan_window_seconds", 60)),
        ),
        system=SystemConfig(
            repo_url=str(system_raw.get("repo_url", DEFAULT_REPO_URL)),
            repo_path=str(system_raw.get("repo_path", DEFAULT_REPO_PATH)),
        ),
        data_dir=data_dir,
    )
    cfg._config_path = config_path
    return cfg


def save_config(cfg: Config, path: Path | None = None) -> Path:
    target = path or cfg.config_path or DEFAULT_CONFIG_PATHS[1]
    target.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "device_id": cfg.device_id,
        "setup_complete": cfg.setup_complete,
        "data_dir": str(cfg.data_dir),
        "honeypot": {
            "persona": cfg.honeypot.persona,
            "hostname": cfg.honeypot.hostname,
            "listen_host": cfg.honeypot.listen_host,
            "ports": cfg.honeypot.ports,
        },
        "notifications": {
            "notify_on_reboot": cfg.notifications.notify_on_reboot,
            "ntfy": {
                "enabled": cfg.notifications.ntfy.enabled,
                "server": cfg.notifications.ntfy.server,
                "topic": cfg.notifications.ntfy.topic,
                "token": cfg.notifications.ntfy.token,
            },
            "webhooks": [
                {
                    "enabled": w.enabled,
                    "name": w.name,
                    "url": w.url,
                }
                for w in cfg.notifications.webhooks
            ],
        },
        "web": {
            "host": cfg.web.host,
            "port": cfg.web.port,
            "setup_token": cfg.web.setup_token,
            "admin_password_hash": cfg.web.admin_password_hash,
            "session_secret": cfg.web.session_secret,
        },
        "detector": {
            "log_source": cfg.detector.log_source,
            "log_path": cfg.detector.log_path,
            "scan_threshold": cfg.detector.scan_threshold,
            "scan_window_seconds": cfg.detector.scan_window_seconds,
        },
        "system": {
            "repo_url": cfg.system.repo_url,
            "repo_path": cfg.system.repo_path,
        },
    }

    with target.open("w") as f:
        yaml.safe_dump(payload, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    cfg._config_path = target
    return target


def repo_url_for(cfg: Config) -> str:
    system = getattr(cfg, "system", None)
    if system and getattr(system, "repo_url", ""):
        return system.repo_url
    return DEFAULT_REPO_URL
