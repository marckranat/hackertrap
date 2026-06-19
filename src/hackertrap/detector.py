from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# iptables LOG lines: SRC=1.2.3.4 DPT=22 PROTO=TCP ...
IPTABLES_RE = re.compile(
    r"SRC=(?P<src>\d+\.\d+\.\d+\.\d+).*?"
    r"DPT=(?P<dpt>\d+).*?"
    r"PROTO=(?P<proto>\w+)",
    re.IGNORECASE,
)

ScanCallback = Callable[[str, str], Awaitable[None]]
ProbeCallback = Callable[[str, str, str], Awaitable[None]]

# Ports watched via iptables logs (can't bind fake services — e.g. SSH uses port 22).
IPTABLES_PROBE_PORTS: dict[int, str] = {22: "ssh"}


class ProbeTracker:
    """Rate-limit single-port probe alerts (one per source IP + port per hour)."""

    def __init__(self, cooldown_seconds: int = 3600) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._last_alert: dict[tuple[str, int], float] = {}

    def should_alert(self, source_ip: str, dest_port: int, now: float | None = None) -> bool:
        if dest_port not in IPTABLES_PROBE_PORTS:
            return False
        ts = now if now is not None else datetime.now(timezone.utc).timestamp()
        key = (source_ip, dest_port)
        last = self._last_alert.get(key)
        if last is not None and ts - last < self.cooldown_seconds:
            return False
        self._last_alert[key] = ts
        return True


class PortScanTracker:
    """Detect scan behaviour: many distinct ports from one IP within a time window."""

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._alerted: set[str] = set()

    def record(self, source_ip: str, dest_port: int, now: float | None = None) -> bool:
        ts = now if now is not None else datetime.now(timezone.utc).timestamp()
        hits = self._hits[source_ip]
        hits.append((ts, dest_port))

        cutoff = ts - self.window_seconds
        while hits and hits[0][0] < cutoff:
            hits.popleft()

        unique_ports = {port for _, port in hits}
        if len(unique_ports) >= self.threshold and source_ip not in self._alerted:
            self._alerted.add(source_ip)
            return True
        return False


class LogDetector:
    def __init__(
        self,
        on_scan: ScanCallback,
        on_probe: ProbeCallback | None = None,
        log_source: str = "auto",
        log_path: str = "/var/log/kern.log",
        scan_threshold: int = 10,
        scan_window_seconds: int = 60,
    ) -> None:
        self.on_scan = on_scan
        self.on_probe = on_probe
        self.log_source = log_source
        self.log_path = Path(log_path)
        self.tracker = PortScanTracker(scan_threshold, scan_window_seconds)
        self.probe_tracker = ProbeTracker()
        self._task: asyncio.Task | None = None

    def _resolve_source(self) -> str:
        if self.log_source != "auto":
            return self.log_source
        if shutil.which("journalctl"):
            return "journal"
        if self.log_path.exists():
            return "file"
        return "none"

    async def start(self) -> None:
        source = self._resolve_source()
        if source == "none":
            logger.warning(
                "No iptables log source found — port scan detection disabled. "
                "Run deploy/iptables/setup.sh on the Pi."
            )
            return

        logger.info("Starting log detector via %s", source)
        self._task = asyncio.create_task(self._tail(source))

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _tail(self, source: str) -> None:
        if source == "journal":
            cmd = [
                "journalctl",
                "-kf",
                "-n",
                "0",
                "_TRANSPORT=kernel",
            ]
        else:
            cmd = ["tail", "-F", "-n", "0", str(self.log_path)]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdout is not None
        try:
            while True:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                await self._process_line(line)
        except asyncio.CancelledError:
            proc.terminate()
            raise

    async def _process_line(self, line: str) -> None:
        if "HACKERTRAP" not in line.upper() and "DPT=" not in line:
            return

        match = IPTABLES_RE.search(line)
        if not match:
            return

        source_ip = match.group("src")
        dest_port = int(match.group("dpt"))
        proto = match.group("proto").upper()

        if self.tracker.record(source_ip, dest_port):
            detail = (
                f"Port scan detected: {self.tracker.threshold}+ ports probed "
                f"within {self.tracker.window_seconds}s ({proto})"
            )
            logger.warning("Scan from %s — %s", source_ip, detail)
            await self.on_scan(source_ip, detail)
            return

        if self.on_probe and self.probe_tracker.should_alert(source_ip, dest_port):
            service = IPTABLES_PROBE_PORTS[dest_port]
            detail = f"{service.upper()} probe on port {dest_port} ({proto})"
            logger.warning("Probe from %s — %s", source_ip, detail)
            await self.on_probe(service, source_ip, detail)


def check_iptables_logging() -> bool:
    """Return True if HACKERTRAP iptables logging rules appear present."""
    try:
        for cmd in (
            ["iptables", "-L", "HACKERTRAP", "-n"],
            ["iptables-nft", "-L", "HACKERTRAP", "-n"],
            ["iptables-legacy", "-L", "HACKERTRAP", "-n"],
        ):
            if not shutil.which(cmd[0]):
                continue
            chain = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if chain.returncode == 0 and "LOG" in chain.stdout.upper():
                return True

        saved = subprocess.run(
            ["iptables-save"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if saved.returncode == 0 and "HACKERTRAP" in saved.stdout.upper():
            return "LOG" in saved.stdout.upper()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False
    return False


def ensure_iptables_logging() -> bool:
    """Apply iptables setup script if logging rules are missing."""
    if check_iptables_logging():
        return True

    script = Path("/opt/hackertrap/deploy/iptables/setup.sh")
    if not script.is_file():
        script = Path(__file__).resolve().parents[2] / "deploy" / "iptables" / "setup.sh"
    if not script.is_file():
        logger.warning("iptables setup script not found at %s", script)
        return False

    logger.info("Applying iptables logging rules via %s", script)
    try:
        result = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if result.stdout:
            logger.info(result.stdout.strip())
        if result.stderr:
            logger.warning(result.stderr.strip())
        if result.returncode != 0:
            logger.error("iptables setup failed (exit %s)", result.returncode)
            return False
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("iptables setup failed: %s", exc)
        return False

    ok = check_iptables_logging()
    if ok:
        logger.info("iptables scan detection enabled")
    else:
        logger.warning("iptables rules applied but verification failed")
    return ok
