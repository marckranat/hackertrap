from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable

from hackertrap.personas import build_decoy_page

logger = logging.getLogger(__name__)

# Plausible first-packet responses — enough to look real, not enough to be useful.
BANNERS: dict[str, bytes] = {
    "ftp": b"220 ProFTPD 1.3.5a Server (Internal Backup) ready.\r\n",
    "telnet": b"\xff\xfd\x25\xff\xfb\x01\xff\xfb\x03\r\n\r\nWelcome to Ubuntu 22.04 LTS\r\nlogin: ",
    "vnc": b"RFB 003.008\n",
}

# Minimal SMB2 header stub (enough for port scanners to see "microsoft-ds").
SMB_NEGOTIATE_STUB = b"\x00\x00\x00\x85\xfeSMB" + b"\x00" * 120

# SSDP reply template — LOCATION filled with device hostname at runtime.
SSDP_REPLY_TEMPLATE = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "EXT:\r\n"
    "LOCATION: http://{host}:1900/rootDesc.xml\r\n"
    "SERVER: Linux/5.15 UPnP/1.0 Internal-Device/1.0\r\n"
    "ST: upnp:rootdevice\r\n"
    "USN: uuid:internal-device::upnp:rootdevice\r\n"
    "\r\n"
)

TCP_SERVICES = frozenset({"ftp", "telnet", "vnc", "http", "smb"})
UDP_SERVICES = frozenset({"snmp", "ssdp"})

AlertCallback = Callable[[str, str, str], Awaitable[None]]

_DISCONNECT_ERRORS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


async def _alert(on_alert: AlertCallback, service: str, source_ip: str, detail: str) -> None:
    await on_alert(service, source_ip, detail)


async def _handle_ftp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_alert: AlertCallback,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    port = writer.get_extra_info("sockname")[1]
    detail = f"FTP connection on port {port}"
    logger.warning("Inbound FTP from %s:%s", source_ip, peer[1] if peer else 0)
    await _alert(on_alert, "ftp", source_ip, detail)

    try:
        writer.write(BANNERS["ftp"])
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=3)
        if data:
            writer.write(b"331 Anonymous login OK, send password.\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=3)
    except (TimeoutError, *_DISCONNECT_ERRORS):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _handle_telnet(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_alert: AlertCallback,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    port = writer.get_extra_info("sockname")[1]
    detail = f"TELNET connection on port {port}"
    logger.warning("Inbound TELNET from %s", source_ip)
    await _alert(on_alert, "telnet", source_ip, detail)

    try:
        writer.write(BANNERS["telnet"])
        await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=5)
    except (TimeoutError, *_DISCONNECT_ERRORS):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _handle_banner_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    service: str,
    on_alert: AlertCallback,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    port = writer.get_extra_info("sockname")[1]
    detail = f"{service.upper()} connection on port {port}"
    logger.warning("Inbound %s from %s", service.upper(), source_ip)
    await _alert(on_alert, service, source_ip, detail)

    try:
        banner = BANNERS.get(service, b"")
        if banner:
            writer.write(banner)
            await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=2)
    except (TimeoutError, *_DISCONNECT_ERRORS):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _handle_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_alert: AlertCallback,
    body: bytes,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    port = writer.get_extra_info("sockname")[1]
    detail = f"HTTP connection on port {port}"
    logger.warning("Inbound HTTP from %s", source_ip)
    await _alert(on_alert, "http", source_ip, detail)

    try:
        await asyncio.wait_for(reader.read(4096), timeout=3)
        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Connection: close\r\n"
            b"Server: nginx/1.18.0\r\n"
            b"Content-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
        )
        writer.write(header + body)
        await writer.drain()
    except (TimeoutError, *_DISCONNECT_ERRORS):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _handle_smb(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_alert: AlertCallback,
) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    port = writer.get_extra_info("sockname")[1]
    detail = f"SMB connection on port {port}"
    logger.warning("Inbound SMB from %s", source_ip)
    await _alert(on_alert, "smb", source_ip, detail)

    try:
        await asyncio.wait_for(reader.read(4096), timeout=3)
        writer.write(SMB_NEGOTIATE_STUB)
        await writer.drain()
    except (TimeoutError, *_DISCONNECT_ERRORS):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


class _UdpProbeProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        service: str,
        port: int,
        on_alert: AlertCallback,
        loop: asyncio.AbstractEventLoop,
        ssdp_host: str = "localhost",
    ) -> None:
        self.service = service
        self.port = port
        self.on_alert = on_alert
        self.loop = loop
        self.ssdp_host = ssdp_host
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]
        detail = f"{self.service.upper()} UDP probe on port {self.port}"
        logger.warning("Inbound %s UDP from %s", self.service.upper(), source_ip)

        async def _notify() -> None:
            await _alert(self.on_alert, self.service, source_ip, detail)

        self.loop.create_task(_notify())

        if self.service == "ssdp" and data.startswith(b"M-SEARCH") and self.transport:
            reply = SSDP_REPLY_TEMPLATE.format(host=self.ssdp_host).encode()
            self.transport.sendto(reply, addr)


def _make_tcp_handler(service: str, on_alert: AlertCallback, http_body: bytes | None = None):
    if service == "ftp":

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await _handle_ftp(reader, writer, on_alert)

        return handler
    if service == "telnet":

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await _handle_telnet(reader, writer, on_alert)

        return handler
    if service == "http":
        body = http_body or b"<html><body>Sign in</body></html>"

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await _handle_http(reader, writer, on_alert, body)

        return handler
    if service == "smb":

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await _handle_smb(reader, writer, on_alert)

        return handler

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle_banner_client(reader, writer, service, on_alert)

    return handler


class HoneypotServer:
    def __init__(
        self,
        listen_host: str,
        ports: dict[str, int],
        on_alert: AlertCallback,
        persona_id: str = "accountserver",
        hostname: str = "accountserver",
    ) -> None:
        self.listen_host = listen_host
        self.ports = ports
        self.on_alert = on_alert
        self.persona_id = persona_id
        self.hostname = hostname
        self.http_body = build_decoy_page(persona_id, hostname).encode("utf-8")
        self._servers: list[asyncio.AbstractServer] = []
        self._udp_transports: list[asyncio.BaseTransport] = []

    async def start(self) -> None:
        loop = asyncio.get_running_loop()

        for service, port in self.ports.items():
            if service in TCP_SERVICES:
                try:
                    handler = _make_tcp_handler(
                        service,
                        self.on_alert,
                        self.http_body if service == "http" else None,
                    )
                    server = await asyncio.start_server(
                        handler,
                        self.listen_host,
                        port,
                    )
                except OSError as exc:
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

            elif service in UDP_SERVICES:
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda s=service, p=port: _UdpProbeProtocol(
                            s, p, self.on_alert, loop, ssdp_host=self.hostname
                        ),
                        local_addr=(self.listen_host, port),
                    )
                except OSError as exc:
                    logger.warning(
                        "Cannot listen on %s UDP port %d — skipping: %s",
                        service.upper(),
                        port,
                        exc,
                    )
                    continue
                self._udp_transports.append(transport)
                logger.info(
                    "Listening for fake %s (UDP) on %s:%d",
                    service.upper(),
                    self.listen_host,
                    port,
                )
            else:
                logger.warning("Unknown honeypot service %r — skipping", service)

        if not self._servers and not self._udp_transports:
            logger.warning("No honeypot services started — check port conflicts in config")

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()

        for transport in self._udp_transports:
            transport.close()
        self._udp_transports.clear()
