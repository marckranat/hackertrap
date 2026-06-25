from pathlib import Path
from unittest.mock import patch

from hackertrap.config import DEFAULT_REPO_PATH, DEFAULT_REPO_URL
from hackertrap.system_ops import (
    consume_reboot_notification,
    get_installed_commit,
    repo_dir,
)


def test_repo_dir_defaults():
    path = repo_dir("", "")
    assert str(path) == DEFAULT_REPO_PATH


def test_default_repo_url():
    assert "marckranat/hackertrap" in DEFAULT_REPO_URL


def test_get_installed_commit_from_marker_file(tmp_path: Path):
    marker = tmp_path / "installed-commit"
    marker.write_text("6ca1d84 Initial commit", encoding="utf-8")
    missing_repo = tmp_path / "no-repo"
    with patch("hackertrap.system_ops.INSTALLED_COMMIT_FILE", marker):
        assert get_installed_commit(missing_repo) == "6ca1d84 Initial commit"


def test_get_last_update_log_shows_latest_session(tmp_path: Path):
    log = tmp_path / "update.log"
    log.write_text(
        "\n".join(
            [
                "--- web-triggered update ---",
                "==> Web update starting at old time",
                "bash: old failure",
                "--- web-triggered update ---",
                "==> Web update starting at new time",
                "OK — HackerTrap updated.",
            ]
        ),
        encoding="utf-8",
    )
    with patch("hackertrap.system_ops.UPDATE_LOG", log):
        from hackertrap.system_ops import get_last_update_log

        text = get_last_update_log()
        assert "new time" in text
        assert "old failure" not in text


def test_consume_reboot_notification_first_boot(tmp_path):
    boot_file = tmp_path / "last_boot_id"
    with (
        patch("hackertrap.system_ops.read_kernel_boot_id", return_value="boot-abc"),
        patch("hackertrap.system_ops.BOOT_ID_FILE", boot_file),
    ):
        assert consume_reboot_notification() is None
        assert boot_file.read_text() == "boot-abc"


def test_consume_reboot_notification_after_reboot(tmp_path):
    boot_file = tmp_path / "last_boot_id"
    boot_file.write_text("boot-old", encoding="utf-8")
    with (
        patch("hackertrap.system_ops.read_kernel_boot_id", return_value="boot-new"),
        patch("hackertrap.system_ops._uptime_seconds", return_value=42.0),
        patch("hackertrap.system_ops.BOOT_ID_FILE", boot_file),
    ):
        detail = consume_reboot_notification()
        assert detail is not None
        assert "Cold boot" in detail
        assert boot_file.read_text() == "boot-new"


def test_consume_reboot_notification_service_restart(tmp_path):
    boot_file = tmp_path / "last_boot_id"
    boot_file.write_text("boot-same", encoding="utf-8")
    with (
        patch("hackertrap.system_ops.read_kernel_boot_id", return_value="boot-same"),
        patch("hackertrap.system_ops.BOOT_ID_FILE", boot_file),
    ):
        assert consume_reboot_notification() is None
