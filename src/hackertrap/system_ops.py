from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

UPDATE_LOG = Path("/var/lib/hackertrap/update.log")
DEFAULT_REPO_URL = "https://github.com/marckranat/hackertrap"
DEFAULT_REPO_PATH = Path("/var/lib/hackertrap/repo")
TZ_PATTERN = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+$")

COMMON_TIMEZONES = (
    "America/Halifax",
    "America/Toronto",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Vancouver",
    "America/Sao_Paulo",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Australia/Sydney",
    "Pacific/Auckland",
    "UTC",
)


def get_timezone() -> str:
    try:
        result = subprocess.run(
            ["timedatectl", "show", "--property=Timezone", "--value"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return result.stdout.strip() or "UTC"
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"


@lru_cache(maxsize=1)
def list_timezones() -> frozenset[str]:
    try:
        result = subprocess.run(
            ["timedatectl", "list-timezones"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return frozenset(line.strip() for line in result.stdout.splitlines() if line.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        return frozenset(COMMON_TIMEZONES)


def set_timezone(timezone: str) -> tuple[bool, str]:
    tz = timezone.strip()
    if not TZ_PATTERN.match(tz):
        return False, "Invalid timezone format"
    if tz not in list_timezones():
        return False, f"Unknown timezone: {tz}"

    try:
        subprocess.run(
            ["timedatectl", "set-timezone", tz],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return True, tz
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        logger.warning("set-timezone failed: %s", detail)
        return False, detail


def repo_dir(configured_path: str = "", configured_url: str = "") -> Path:
    """Return the standard local clone path (GitHub is the source of truth)."""
    path = Path(configured_path.strip() or DEFAULT_REPO_PATH)
    _ = configured_url or DEFAULT_REPO_URL  # reserved for sync-repo
    return path


def get_installed_commit(repo_path: Path | None = None) -> str:
    path = repo_path or DEFAULT_REPO_PATH
    if not (path / ".git").is_dir():
        return "not installed"
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "log", "-1", "--format=%h %s"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return "unknown"


def get_last_update_log(lines: int = 5) -> str:
    if not UPDATE_LOG.is_file():
        return ""
    try:
        text = UPDATE_LOG.read_text(encoding="utf-8", errors="replace")
        tail = [ln for ln in text.strip().splitlines() if ln.strip()][-lines:]
        return "\n".join(tail)
    except OSError:
        return ""


async def trigger_update(repo_path: Path, repo_url: str = DEFAULT_REPO_URL) -> tuple[bool, str]:
    script = Path(__file__).resolve().parents[2] / "deploy" / "update-web.sh"
    if not script.is_file():
        # Installed layout: /opt/hackertrap/deploy/update-web.sh
        script = Path("/opt/hackertrap/deploy/update-web.sh")
    if not script.is_file():
        return False, f"Update script not found at {script}"

    UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_handle = UPDATE_LOG.open("a", encoding="utf-8")
    log_handle.write("\n--- web-triggered update ---\n")
    log_handle.flush()

    try:
        proc = await asyncio.create_subprocess_exec(
            "bash",
            str(script),
            str(repo_path),
            repo_url,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
        )
    except OSError as exc:
        log_handle.close()
        return False, str(exc)

    log_handle.close()
    logger.info("Update triggered (pid %s) repo=%s url=%s", proc.pid, repo_path, repo_url)
    return True, repo_url
