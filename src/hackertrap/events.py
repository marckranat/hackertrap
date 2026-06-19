from __future__ import annotations

import logging
from pathlib import Path

from hackertrap.alerts import dispatch_alert
from hackertrap.config import Config
from hackertrap.db import record_alert

logger = logging.getLogger(__name__)


class EventHandler:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    @property
    def db_path(self) -> Path:
        return self.cfg.db_path

    async def handle_service_hit(self, service: str, source_ip: str, detail: str) -> None:
        event_type = f"{service}_connection"
        title = f"HackerTrap: {service.upper()} probe from {source_ip}"
        message = (
            f"Device: {self.cfg.honeypot.hostname}\n"
            f"Event: {detail}\n"
            f"Source: {source_ip}\n"
            f"ID: {self.cfg.device_id}"
        )
        notified = await dispatch_alert(self.cfg, title, message)
        await record_alert(self.db_path, event_type, source_ip, detail, notified=notified)

    async def handle_port_scan(self, source_ip: str, detail: str) -> None:
        title = f"HackerTrap: port scan from {source_ip}"
        message = (
            f"Device: {self.cfg.honeypot.hostname}\n"
            f"Event: {detail}\n"
            f"Source: {source_ip}\n"
            f"ID: {self.cfg.device_id}"
        )
        notified = await dispatch_alert(self.cfg, title, message)
        await record_alert(self.db_path, "port_scan", source_ip, detail, notified=notified)

    async def send_test_alert(self) -> bool:
        title = "HackerTrap test alert"
        message = (
            f"This is a test notification from {self.cfg.honeypot.hostname}.\n"
            f"Device ID: {self.cfg.device_id}\n"
            "If you received this, alerts are working."
        )
        ok = await dispatch_alert(self.cfg, title, message)
        if ok:
            await record_alert(
                self.db_path,
                "test",
                "127.0.0.1",
                "Manual test notification",
                notified=True,
            )
        return ok
