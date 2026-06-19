from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

# Captured from real service banners — enough to look plausible, not enough to be useful.
BANNERS: dict[str, bytes] = {
    "ftp": b"220 ProFTPD 1.3.5a Server (Internal Backup) [192.168.1.50]\r\n",
    "telnet": b"\xff\xfd\x25",
    "vnc": b"RFB 003.008\n",
    "ssh": b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n",
}


AlertCallback = Callable[[str, str, str], Awaitable[None]]

# Scanners often connect, grab a banner, and hang up — not a real error.
_DISCONNECT_ERRORS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    service: str,
    on_alert: AlertCallback,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    source_port = peer[1] if peer else 0

    detail = f"{service.upper()} connection on port {writer.get_extra_info('sockname')[1]}"
    logger.warning("Inbound %s from %s:%s", service.upper(), source_ip, source_port)

    try:
        await on_alert(service, source_ip, detail)
        banner = BANNERS.get(service, b"")
        if banner:
            writer.write(banner)
            try:
                await writer.drain()
            except _DISCONNECT_ERRORS:
                pass  # normal scanner behaviour
        if service == "ssh":
            try:
                await asyncio.wait_for(reader.read(256), timeout=2)
            except (TimeoutError, *_DISCONNECT_ERRORS):
                pass
    except _DISCONNECT_ERRORS:
        pass
    except Exception:
        logger.exception("Error handling %s connection from %s", service, source_ip)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _make_handler(service: str, on_alert: AlertCallback):
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle_client(reader, writer, service, on_alert)

    return handler


class HoneypotServer:
    def __init__(self, listen_host: str, ports: dict[str, int], on_alert: AlertCallback) -> None:
        self.listen_host = listen_host
        self.ports = ports
        self.on_alert = on_alert
        self._servers: list[asyncio.AbstractServer] = []

    async def start(self) -> None:
        for service, port in self.ports.items():
            if service not in BANNERS:
                logger.warning("Unknown honeypot service %r — skipping", service)
                continue
            try:
                server = await asyncio.start_server(
                    _make_handler(service, self.on_alert),
                    self.listen_host,
                    port,
                )
            except OSError as exc:
                if service == "ssh" and port == 22:
                    logger.info(
                        "SSH honeypot skipped on port 22 (real SSH uses this port) — "
                        "SSH probes are detected via network logging"
                    )
                else:
                    logger.warning(
                        "Cannot listen on %s port %d (%s) — skipping: %s",
                        service.upper(),
                        port,
                        self.listen_host,
                        exc,
                    )
                continue
            self._servers.append(server)
            logger.info("Listening for fake %s on %s:%d", service.upper(), self.listen_host, port)

        if not self._servers:
            logger.warning("No honeypot services started — check port conflicts in config")

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()
