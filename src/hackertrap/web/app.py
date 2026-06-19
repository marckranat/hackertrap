from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from hackertrap import __version__
from hackertrap.alerts import build_channels
from hackertrap.config import DEFAULT_HOSTNAME, Config, normalize_ntfy_topic, repo_url_for, save_config
from hackertrap.db import alert_count, list_alerts
from hackertrap.detector import check_iptables_logging, ensure_iptables_logging
from hackertrap.events import EventHandler
from hackertrap.system_ops import (
    COMMON_TIMEZONES,
    get_installed_commit,
    get_last_update_log,
    get_timezone,
    repo_dir,
    set_timezone,
    trigger_update,
)
from hackertrap.web.auth import (
    SESSION_COOKIE,
    auth_required,
    make_session_token,
    set_password,
    verify_password,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

if not TEMPLATES_DIR.is_dir():
    raise RuntimeError(
        f"Web templates not found at {TEMPLATES_DIR}. "
        "Reinstall with: sudo pip install -e /opt/hackertrap"
    )


def _uptime_since(started: datetime) -> str:
    delta = datetime.now(timezone.utc) - started
    hours, rem = divmod(int(delta.total_seconds()), 3600)
    minutes, _ = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "unknown"


def _system_hostname() -> str:
    try:
        return socket.gethostname().split(".")[0]
    except OSError:
        return "unknown"


def create_app(cfg: Config, events: EventHandler, started_at: datetime) -> FastAPI:
    app = FastAPI(title="HackerTrap", docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def ctx(request: Request, **extra):
        return {
            "request": request,
            "cfg": cfg,
            "device_id": cfg.device_id,
            "hostname": cfg.honeypot.hostname,
            "system_hostname": _system_hostname(),
            "started_at": started_at,
            "uptime": _uptime_since(started_at),
            "local_ip": _local_ip(),
            "version": __version__,
            "admin_password_set": bool(cfg.web.admin_password_hash),
            **extra,
        }

    def require_login(request: Request) -> RedirectResponse | None:
        if auth_required(cfg, request):
            return None
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    def apply_notifications(
        ntfy_topic_raw: str,
        ntfy_server: str,
        ntfy_token: str,
        webhook_url: str,
        webhook_name: str,
        ntfy_enabled: str = "",
        webhook_enabled: str = "",
    ) -> None:
        topic = normalize_ntfy_topic(ntfy_topic_raw)
        cfg.notifications.ntfy.topic = topic
        cfg.notifications.ntfy.server = ntfy_server.strip() or "https://ntfy.sh"
        cfg.notifications.ntfy.token = ntfy_token.strip()
        cfg.notifications.ntfy.enabled = ntfy_enabled == "on" or bool(topic)

        cfg.notifications.webhooks = []
        url = webhook_url.strip()
        if webhook_enabled == "on" or url:
            from hackertrap.config import WebhookConfig

            cfg.notifications.webhooks.append(
                WebhookConfig(
                    enabled=True,
                    url=url,
                    name=webhook_name.strip() or "webhook",
                )
            )

        save_config(cfg)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not cfg.setup_complete:
            return RedirectResponse("/setup", status_code=303)
        if redirect := require_login(request):
            return redirect

        alerts = await list_alerts(cfg.db_path, limit=50)
        total = await alert_count(cfg.db_path)
        channels = [c.name for c in build_channels(cfg)]
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            ctx(
                request,
                alerts=alerts,
                total_alerts=total,
                channels=channels,
                iptables_ok=check_iptables_logging(),
                ports=cfg.honeypot.ports,
            ),
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/"):
        if not cfg.setup_complete or not cfg.web.admin_password_hash:
            return RedirectResponse("/", status_code=303)
        if auth_required(cfg, request):
            return RedirectResponse(next or "/", status_code=303)
        return templates.TemplateResponse(
            request,
            "login.html",
            ctx(request, next=next, password_saved=request.query_params.get("saved") == "password"),
        )

    @app.post("/login")
    async def login_submit(
        request: Request,
        password: str = Form(...),
        next: str = Form(default="/"),
    ):
        if not verify_password(password, cfg.web.admin_password_hash):
            return RedirectResponse("/login?error=1", status_code=303)

        token = make_session_token(cfg)
        save_config(cfg)
        response = RedirectResponse(next or "/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 7,
        )
        return response

    @app.post("/logout")
    async def logout():
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request, token: str = ""):
        if cfg.setup_complete:
            return RedirectResponse("/", status_code=303)
        if token and token != cfg.web.setup_token:
            raise HTTPException(status_code=403, detail="Invalid setup token")

        return templates.TemplateResponse(
            request,
            "setup.html",
            ctx(request, setup_token=cfg.web.setup_token),
        )

    @app.post("/setup")
    async def setup_submit(
        token: str = Form(...),
        hostname: str = Form(...),
        admin_password: str = Form(...),
        ntfy_enabled: str = Form(default=""),
        ntfy_server: str = Form(default="https://ntfy.sh"),
        ntfy_topic: str = Form(default=""),
        ntfy_token: str = Form(default=""),
        webhook_enabled: str = Form(default=""),
        webhook_url: str = Form(default=""),
        webhook_name: str = Form(default="discord"),
    ):
        if cfg.setup_complete:
            return RedirectResponse("/", status_code=303)
        if token != cfg.web.setup_token:
            raise HTTPException(status_code=403, detail="Invalid setup token")
        if len(admin_password.strip()) < 8:
            raise HTTPException(status_code=400, detail="Admin password must be at least 8 characters")

        cfg.honeypot.hostname = hostname.strip()[:64] or DEFAULT_HOSTNAME
        set_password(cfg, admin_password.strip())
        apply_notifications(
            ntfy_topic,
            ntfy_server,
            ntfy_token,
            webhook_url,
            webhook_name,
            ntfy_enabled,
            webhook_enabled,
        )
        cfg.setup_complete = True
        save_config(cfg)

        response = RedirectResponse("/", status_code=303)
        response.set_cookie(SESSION_COOKIE, make_session_token(cfg), httponly=True, samesite="lax")
        return response

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        if not cfg.setup_complete:
            return RedirectResponse("/setup", status_code=303)
        if redirect := require_login(request):
            return redirect

        ntfy = cfg.notifications.ntfy
        webhook = cfg.notifications.webhooks[0] if cfg.notifications.webhooks else None
        return templates.TemplateResponse(
            request,
            "settings.html",
            ctx(
                request,
                ntfy_server=ntfy.server,
                ntfy_topic=ntfy.topic,
                ntfy_token=ntfy.token,
                webhook_url=webhook.url if webhook else "",
                webhook_name=webhook.name if webhook else "discord",
                timezone=get_timezone(),
                common_timezones=COMMON_TIMEZONES,
                repo_url=repo_url_for(cfg),
                installed_commit=get_installed_commit(repo_dir(cfg.system.repo_path)),
                last_update_log=get_last_update_log(),
            ),
        )

    @app.post("/settings")
    async def settings_submit(
        request: Request,
        ntfy_server: str = Form(default="https://ntfy.sh"),
        ntfy_topic: str = Form(default=""),
        ntfy_token: str = Form(default=""),
        webhook_url: str = Form(default=""),
        webhook_name: str = Form(default="discord"),
    ):
        if not cfg.setup_complete:
            raise HTTPException(status_code=400, detail="Complete setup first")
        if redirect := require_login(request):
            return redirect

        apply_notifications(
            ntfy_topic,
            ntfy_server,
            ntfy_token,
            webhook_url,
            webhook_name,
        )
        return RedirectResponse("/settings?saved=1", status_code=303)

    @app.post("/settings/password")
    async def settings_password(
        request: Request,
        new_password: str = Form(...),
        confirm_password: str = Form(...),
    ):
        if not cfg.setup_complete:
            raise HTTPException(status_code=400, detail="Complete setup first")
        if redirect := require_login(request):
            return redirect
        if len(new_password) < 8:
            return RedirectResponse("/settings?error=Password+must+be+at+least+8+characters", status_code=303)
        if new_password != confirm_password:
            return RedirectResponse("/settings?error=Passwords+do+not+match", status_code=303)

        set_password(cfg, new_password)
        token = make_session_token(cfg)
        save_config(cfg)
        response = RedirectResponse("/login?next=/settings&saved=password", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 7,
        )
        return response

    @app.post("/settings/timezone")
    async def settings_timezone(
        request: Request,
        timezone: str = Form(...),
    ):
        if not cfg.setup_complete:
            raise HTTPException(status_code=400, detail="Complete setup first")
        if redirect := require_login(request):
            return redirect

        ok, detail = set_timezone(timezone)
        if not ok:
            return RedirectResponse(f"/settings?error={detail}", status_code=303)
        return RedirectResponse("/settings?saved=timezone", status_code=303)

    @app.post("/settings/update")
    async def settings_update(request: Request):
        if not cfg.setup_complete:
            raise HTTPException(status_code=400, detail="Complete setup first")
        if redirect := require_login(request):
            return redirect

        path = repo_dir(
            getattr(getattr(cfg, "system", None), "repo_path", "") or "",
            repo_url_for(cfg),
        )
        ok, detail = await trigger_update(path, repo_url_for(cfg))
        if not ok:
            return RedirectResponse(f"/settings?error={detail}", status_code=303)
        return RedirectResponse("/settings?saved=update", status_code=303)

    @app.post("/settings/iptables")
    async def settings_iptables(request: Request):
        if not cfg.setup_complete:
            raise HTTPException(status_code=400, detail="Complete setup first")
        if redirect := require_login(request):
            return redirect

        ok = ensure_iptables_logging()
        if not ok:
            return RedirectResponse(
                "/settings?error=Could+not+enable+iptables+logging.+Check+sudo+journalctl+-u+hackertrap",
                status_code=303,
            )
        return RedirectResponse("/settings?saved=iptables", status_code=303)

    @app.get("/notifications/status")
    async def notifications_status(request: Request):
        if redirect := require_login(request):
            return redirect
        ntfy = cfg.notifications.ntfy
        channels = build_channels(cfg)
        return {
            "ntfy": {
                "enabled": ntfy.enabled,
                "server": ntfy.server,
                "topic": ntfy.topic,
                "has_token": bool(ntfy.token),
            },
            "webhooks": [
                {"name": w.name, "enabled": w.enabled, "url_set": bool(w.url)}
                for w in cfg.notifications.webhooks
            ],
            "active_channels": [c.name for c in channels],
        }

    @app.post("/test-alert")
    async def test_alert(request: Request):
        if not cfg.setup_complete:
            raise HTTPException(status_code=400, detail="Complete setup first")
        if redirect := require_login(request):
            return redirect

        channels = build_channels(cfg)
        if not channels:
            detail = "No notification channels configured. Add your ntfy topic in Settings."
            if "application/json" in request.headers.get("accept", ""):
                raise HTTPException(status_code=400, detail=detail)
            return RedirectResponse(f"/settings?error={detail}", status_code=303)

        ok = await events.send_test_alert()
        if not ok:
            detail = "Notification send failed — check your ntfy topic in Settings."
            if "application/json" in request.headers.get("accept", ""):
                raise HTTPException(status_code=502, detail=detail)
            return RedirectResponse(f"/settings?error={detail}", status_code=303)

        if "application/json" in request.headers.get("accept", ""):
            return {"status": "ok", "message": "Test alert sent"}
        return RedirectResponse("/?test=ok", status_code=303)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__}

    return app
