from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hackertrap.config import Config

SESSION_COOKIE = "hackertrap_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
PBKDF2_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or not password:
        return False
    try:
        scheme, iterations, salt, digest_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        expected = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        )
        return hmac.compare_digest(expected.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def ensure_session_secret(cfg: Config) -> None:
    if not cfg.web.session_secret:
        cfg.web.session_secret = secrets.token_urlsafe(32)


def _sign(value: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_token(cfg: Config) -> str:
    ensure_session_secret(cfg)
    payload = secrets.token_urlsafe(16)
    return f"{payload}.{_sign(payload, cfg.web.session_secret)}"


def verify_session_token(cfg: Config, token: str | None) -> bool:
    if not token or not cfg.web.session_secret:
        return False
    try:
        payload, signature = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = _sign(payload, cfg.web.session_secret)
    return hmac.compare_digest(signature, expected)


def auth_required(cfg: Config, request) -> bool:
    """Return True if this request may access protected pages."""
    if not cfg.setup_complete:
        return True
    if not cfg.web.admin_password_hash:
        return True
    return verify_session_token(cfg, request.cookies.get(SESSION_COOKIE))


def set_password(cfg: Config, password: str) -> None:
    ensure_session_secret(cfg)
    cfg.web.admin_password_hash = hash_password(password)
