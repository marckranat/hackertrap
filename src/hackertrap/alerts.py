from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from hackertrap.config import Config

logger = logging.getLogger(__name__)


class AlertChannel(ABC):
    name: str

    @abstractmethod
    async def send(self, title: str, message: str) -> bool:
        ...


class NtfyChannel(AlertChannel):
    name = "ntfy"

    def __init__(self, server: str, topic: str, token: str = "") -> None:
        self.server = server.rstrip("/")
        self.topic = topic
        self.token = token

    async def send(self, title: str, message: str) -> bool:
        if not self.topic:
            return False

        headers = {"Title": title, "Priority": "high", "Tags": "warning,skull"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"{self.server}/{self.topic}"
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    url,
                    content=message.encode("utf-8"),
                    headers=headers,
                )
                response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            detail = str(exc)
            if isinstance(exc, httpx.HTTPStatusError):
                detail = f"{exc.response.status_code} {exc.response.text[:200]}"
            logger.warning("ntfy alert failed (%s): %s", url, detail)
            return False


class WebhookChannel(AlertChannel):
    name = "webhook"

    def __init__(self, url: str, label: str = "webhook") -> None:
        self.url = url
        self.label = label

    async def send(self, title: str, message: str) -> bool:
        if not self.url:
            return False

        payload = {
            "content": f"**{title}**\n{message}",
            "username": "HackerTrap",
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.url, json=payload)
                response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            logger.warning("webhook alert failed (%s): %s", self.label, exc)
            return False


def build_channels(cfg: Config) -> list[AlertChannel]:
    channels: list[AlertChannel] = []
    ntfy = cfg.notifications.ntfy
    if ntfy.enabled and ntfy.topic:
        channels.append(NtfyChannel(ntfy.server, ntfy.topic, ntfy.token))

    for webhook in cfg.notifications.webhooks:
        if webhook.enabled and webhook.url:
            channels.append(WebhookChannel(webhook.url, webhook.name))

    return channels


async def dispatch_alert(cfg: Config, title: str, message: str) -> bool:
    channels = build_channels(cfg)
    if not channels:
        logger.info("No notification channels configured; alert logged only")
        return False

    results = []
    for channel in channels:
        ok = await channel.send(title, message)
        results.append(ok)
        logger.info("Alert via %s: %s", channel.name, "ok" if ok else "failed")

    return any(results)
