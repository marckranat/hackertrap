from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from datetime import datetime, timezone
from pathlib import Path

import uvicorn

from hackertrap.config import Config, load_config, save_config
from hackertrap.db import init_db
from hackertrap.detector import LogDetector, ensure_iptables_logging
from hackertrap.events import EventHandler
from hackertrap.honeypot import HoneypotServer
from hackertrap.web.app import create_app

logger = logging.getLogger(__name__)


class HackerTrap:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.started_at = datetime.now(timezone.utc)
        self.events = EventHandler(cfg)
        self.honeypot = HoneypotServer(
            cfg.honeypot.listen_host,
            cfg.honeypot.ports,
            self.events.handle_service_hit,
        )
        self.detector = LogDetector(
            self.events.handle_port_scan,
            on_probe=self.events.handle_service_hit,
            log_source=cfg.detector.log_source,
            log_path=cfg.detector.log_path,
            scan_threshold=cfg.detector.scan_threshold,
            scan_window_seconds=cfg.detector.scan_window_seconds,
        )
        self.app = create_app(cfg, self.events, self.started_at)

    async def run(self) -> None:
        await init_db(self.cfg.db_path)

        if self.cfg.config_path is None:
            # First run — persist config so the setup token survives restarts.
            save_path = self.cfg.data_dir / "config.yaml"
            try:
                self.cfg.data_dir.mkdir(parents=True, exist_ok=True)
                save_config(self.cfg, save_path)
            except PermissionError:
                self.cfg.data_dir = Path("./data")
                self.cfg.data_dir.mkdir(parents=True, exist_ok=True)
                save_path = Path("config.local.yaml")
                save_config(self.cfg, save_path)
            logger.info("Created initial config at %s", save_path)
            logger.info("Setup token: %s", self.cfg.web.setup_token)

        config = uvicorn.Config(
            self.app,
            host=self.cfg.web.host,
            port=self.cfg.web.port,
            log_level="info",
        )
        server = uvicorn.Server(config)

        def _shutdown(*_args):
            logger.info("Shutdown signal received")
            server.should_exit = True

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _shutdown)

        async def background_services() -> None:
            if not ensure_iptables_logging():
                logger.warning(
                    "Port scan detection unavailable — run: sudo bash /opt/hackertrap/deploy/iptables/setup.sh"
                )
            await self.honeypot.start()
            await self.detector.start()
            try:
                await asyncio.Event().wait()
            finally:
                await self.detector.stop()
                await self.honeypot.stop()

        bg = asyncio.create_task(background_services())

        logger.info(
            "HackerTrap running — web UI http://%s:%d  device=%s",
            self.cfg.web.host,
            self.cfg.web.port,
            self.cfg.device_id,
        )

        try:
            await server.serve()
        finally:
            bg.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await bg


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    cfg = load_config()
    trap = HackerTrap(cfg)
    asyncio.run(trap.run())


if __name__ == "__main__":
    main()
