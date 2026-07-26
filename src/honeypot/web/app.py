from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from honeypot.config import Settings
from honeypot.limits import ConnectionLimiter
from honeypot.port_manager import PortManager
from honeypot.server import HoneypotServer
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore
from honeypot.web.auth import LoginGuard, constant_time_equal

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def create_app(
    settings: Settings,
    store: SqliteStore,
    pipeline: EventPipeline,
    server: HoneypotServer,
    port_manager: PortManager,
    limiter: ConnectionLimiter,
) -> FastAPI:
    app = FastAPI(title="Proxy Honeypot", docs_url=None, redoc_url=None)
    secret = settings.web_session_secret or settings.web_password or "insecure-dev-secret"
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie="honeypot_session",
        same_site="lax",
        https_only=False,
        max_age=60 * 60 * 12,
    )
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    guard = LoginGuard(
        max_failures=settings.web_login_max_failures,
        ban_minutes=settings.web_login_ban_minutes,
    )

    def client_ip(request: Request) -> str:
        if request.client:
            return request.client.host
        return "unknown"

    def require_login(request: Request) -> None:
        if not request.session.get("user"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")

    def logged_in(request: Request) -> bool:
        return bool(request.session.get("user"))

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Any:
        if logged_in(request):
            return RedirectResponse("/", status_code=302)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": None},
        )

    @app.post("/login")
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ) -> Any:
        ip = client_ip(request)
        if guard.is_banned(ip):
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Too many failures. Try later."},
                status_code=429,
            )
        user_ok = constant_time_equal(username, settings.web_auth_user)
        # Pad password compare if empty configured password
        expected = settings.web_password or ""
        if not expected:
            guard.register_failure(ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "WEB_PASSWORD is not configured on server."},
                status_code=500,
            )
        pass_ok = constant_time_equal(password, expected)
        if not (user_ok and pass_ok):
            guard.register_failure(ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Invalid username or password."},
                status_code=401,
            )
        guard.register_success(ip)
        request.session["user"] = username
        return RedirectResponse("/", status_code=302)

    @app.get("/logout")
    async def logout(request: Request) -> Any:
        request.session.clear()
        return RedirectResponse("/login", status_code=302)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        now = datetime.now(timezone.utc)
        day_ago = (now - timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
        week_ago = (now - timedelta(days=7)).isoformat(timespec="seconds").replace("+00:00", "Z")
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "user": request.session.get("user"),
                "all_time": store.summary_stats(),
                "day": store.summary_stats(day_ago),
                "week": store.summary_stats(week_ago),
                "pipeline": pipeline.stats(),
                "limiter": limiter.snapshot(),
                "ports": port_manager.list_with_status(),
                "recent_auth": store.recent_events(20, event_type="auth"),
            },
        )

    @app.get("/credentials", response_class=HTMLResponse)
    async def credentials_page(request: Request) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request,
            "credentials.html",
            {
                "user": request.session.get("user"),
                "items": store.top_credentials(500),
            },
        )

    @app.get("/sources", response_class=HTMLResponse)
    async def sources_page(request: Request) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request,
            "sources.html",
            {
                "user": request.session.get("user"),
                "items": store.list_sources(500),
            },
        )

    @app.get("/events", response_class=HTMLResponse)
    async def events_page(request: Request) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request,
            "events.html",
            {
                "user": request.session.get("user"),
                "items": store.recent_events(200),
            },
        )

    @app.get("/ports", response_class=HTMLResponse)
    async def ports_page(request: Request, error: str | None = None, ok: str | None = None) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request,
            "ports.html",
            {
                "user": request.session.get("user"),
                "ports": port_manager.list_with_status(),
                "error": error,
                "ok": ok,
            },
        )

    @app.post("/ports/add")
    async def ports_add(
        request: Request,
        port: int = Form(...),
        primary: str = Form("http_proxy"),
        note: str = Form(""),
    ) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        try:
            await port_manager.add_port(port=port, primary=primary, note=note, enable=True)
            return RedirectResponse("/ports?ok=added", status_code=302)
        except Exception as e:
            return RedirectResponse(f"/ports?error={e}", status_code=302)

    @app.post("/ports/{port}/disable")
    async def ports_disable(request: Request, port: int) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        try:
            await port_manager.disable_port(port)
            return RedirectResponse("/ports?ok=disabled", status_code=302)
        except Exception as e:
            return RedirectResponse(f"/ports?error={e}", status_code=302)

    @app.post("/ports/{port}/enable")
    async def ports_enable(request: Request, port: int) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        try:
            await port_manager.enable_port(port)
            return RedirectResponse("/ports?ok=enabled", status_code=302)
        except Exception as e:
            return RedirectResponse(f"/ports?error={e}", status_code=302)

    # --- JSON API ---

    @app.get("/api/stats/summary")
    async def api_summary(request: Request) -> Any:
        require_login(request)
        now = datetime.now(timezone.utc)
        day_ago = (now - timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
        return {
            "all_time": store.summary_stats(),
            "last_24h": store.summary_stats(day_ago),
            "pipeline": pipeline.stats(),
            "limiter": limiter.snapshot(),
        }

    @app.get("/api/credentials")
    async def api_credentials(request: Request, limit: int = 100) -> Any:
        require_login(request)
        return store.top_credentials(min(limit, 1000))

    @app.get("/api/sources")
    async def api_sources(request: Request, limit: int = 100) -> Any:
        require_login(request)
        return store.list_sources(min(limit, 1000))

    @app.get("/api/events")
    async def api_events(request: Request, limit: int = 100, event_type: str | None = None) -> Any:
        require_login(request)
        return store.recent_events(min(limit, 500), event_type=event_type)

    @app.get("/api/ports")
    async def api_ports(request: Request) -> Any:
        require_login(request)
        return port_manager.list_with_status()

    @app.post("/api/ports")
    async def api_ports_add(request: Request) -> Any:
        require_login(request)
        body = await request.json()
        try:
            cfg = await port_manager.add_port(
                port=int(body["port"]),
                primary=str(body.get("primary") or "http_proxy"),
                also_accept=body.get("also_accept"),
                note=str(body.get("note") or ""),
                enable=bool(body.get("enabled", True)),
            )
            return {
                "port": cfg.port,
                "primary": cfg.primary.value,
                "also_accept": [x.value for x in cfg.also_accept],
                "enabled": cfg.enabled,
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/ports/{port}/enable")
    async def api_port_enable(request: Request, port: int) -> Any:
        require_login(request)
        try:
            cfg = await port_manager.enable_port(port)
            return {"port": cfg.port, "enabled": True}
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/api/ports/{port}/disable")
    async def api_port_disable(request: Request, port: int) -> Any:
        require_login(request)
        try:
            await port_manager.disable_port(port)
            return {"port": port, "enabled": False}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/system")
    async def api_system(request: Request) -> Any:
        require_login(request)
        raw_dir = settings.data_dir / "raw"
        raw_files = sorted(raw_dir.glob("events-*.jsonl")) if raw_dir.exists() else []
        return {
            "data_dir": str(settings.data_dir),
            "sqlite": str(settings.sqlite_path),
            "auth_mode": settings.effective_auth_mode.value,
            "jsonl_files": [p.name for p in raw_files[-14:]],
            "pipeline": pipeline.stats(),
            "limiter": limiter.snapshot(),
            "listening": server.listening_ports(),
            "version": "0.1.0",
        }

    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException) -> Any:
        if exc.status_code == 401 and request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=401)
        if exc.status_code == 401:
            return RedirectResponse("/login", status_code=302)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
