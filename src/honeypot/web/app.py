from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from honeypot import __version__
from honeypot.ai_client import AiClientError, chat_completion, fetch_models
from honeypot.ai_context import PRESET_PROMPTS, build_analysis_context, context_as_prompt_block
from honeypot.ai_settings import AiSettings, AiSettingsStore
from honeypot.config import Settings
from honeypot.limits import ConnectionLimiter
from honeypot.ops import disk_usage_report
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
    ai_store = AiSettingsStore(settings.data_dir / "ai_settings.json")

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

    @app.get("/system", response_class=HTMLResponse)
    async def system_page(request: Request) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        disk = disk_usage_report(settings.data_dir)
        return templates.TemplateResponse(
            request,
            "system.html",
            {
                "user": request.session.get("user"),
                "disk": disk,
                "pipeline": pipeline.stats(),
                "limiter": limiter.snapshot(),
                "listening": server.listening_ports(),
                "auth_mode": settings.effective_auth_mode.value,
                "events_retention_days": settings.events_retention_days,
                "jsonl_retention_days": settings.jsonl_retention_days,
                "auth_stale_warn_hours": settings.auth_stale_warn_hours,
                "auto_export_hours": settings.auto_export_hours,
                "event_count": store.event_count(),
                "last_auth": store.last_auth_ts(),
                "version": __version__,
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

    # --- AI settings + chat (config persisted in DATA_DIR/ai_settings.json) ---

    @app.get("/ai", response_class=HTMLResponse)
    async def ai_page(request: Request) -> Any:
        if not logged_in(request):
            return RedirectResponse("/login", status_code=302)
        ai = ai_store.load()
        return templates.TemplateResponse(
            request,
            "ai.html",
            {
                "user": request.session.get("user"),
                "ai": ai.public_dict(mask_key=True),
                "presets": PRESET_PROMPTS,
            },
        )

    @app.get("/api/ai/settings")
    async def api_ai_settings_get(request: Request) -> Any:
        require_login(request)
        return ai_store.load().public_dict(mask_key=True)

    @app.post("/api/ai/settings")
    async def api_ai_settings_save(request: Request) -> Any:
        require_login(request)
        body = await request.json()
        saved = ai_store.update_from_payload(body)
        return {
            "ok": True,
            "settings": saved.public_dict(mask_key=True),
            "normalized_base_url": saved.base_url,
        }

    @app.post("/api/ai/models")
    async def api_ai_models(request: Request) -> Any:
        require_login(request)
        body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
        cfg = ai_store.load()
        # allow one-shot override without permanent save of secrets unless full save
        if body.get("base_url"):
            cfg.base_url = str(body["base_url"]).strip()
        if body.get("api_key") and not str(body["api_key"]).startswith("*"):
            cfg.api_key = str(body["api_key"]).strip()
        if body.get("provider"):
            cfg.provider = str(body["provider"]).strip().lower()
        try:
            result = await fetch_models(cfg)
            # persist detection + normalized base when config already on disk
            persisted = ai_store.load()
            persisted.base_url = result.get("base_url") or cfg.base_url
            if result.get("provider"):
                persisted.detected_provider = str(result["provider"])
            if cfg.api_key and not persisted.api_key:
                persisted.api_key = cfg.api_key
            ai_store.save(persisted)
            models = result.get("models") or []
            return {
                "models": models,
                "count": len(models),
                "provider": result.get("provider"),
                "base_url": result.get("base_url"),
                "notes": result.get("notes") or [],
            }
        except AiClientError as e:
            raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e

    @app.post("/api/ai/chat")
    async def api_ai_chat(request: Request) -> Any:
        require_login(request)
        body = await request.json()
        cfg = ai_store.load()
        if not cfg.is_ready():
            raise HTTPException(
                status_code=400,
                detail="AI 未配置完整：请在页面保存 endpoint / API Key / 模型，并启用 AI",
            )
        user_msg = str(body.get("message") or "").strip()
        if not user_msg:
            raise HTTPException(status_code=400, detail="message required")
        include_data = bool(body.get("include_data", True))
        history = body.get("history") or []
        messages: list[dict[str, str]] = [
            {"role": "system", "content": cfg.system_prompt or AiSettings().system_prompt},
        ]
        if include_data:
            ctx = build_analysis_context(
                store,
                settings.data_dir,
                listening=server.listening_ports(),
                auth_mode=settings.effective_auth_mode.value,
            )
            messages.append(
                {
                    "role": "system",
                    "content": context_as_prompt_block(ctx),
                }
            )
        if isinstance(history, list):
            for h in history[-20:]:
                if not isinstance(h, dict):
                    continue
                role = h.get("role")
                content = h.get("content")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": str(content)[:8000]})
        messages.append({"role": "user", "content": user_msg[:12000]})
        try:
            result = await chat_completion(cfg, messages)
        except AiClientError as e:
            raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e
        if result.get("provider"):
            cfg.detected_provider = str(result["provider"])
            ai_store.save(cfg)
        return {
            "content": result["content"],
            "model": result.get("model"),
            "usage": result.get("usage"),
            "provider": result.get("provider"),
            "included_data": include_data,
        }

    @app.post("/api/ai/analyze")
    async def api_ai_analyze(request: Request) -> Any:
        require_login(request)
        body = await request.json()
        preset = str(body.get("preset") or "overview")
        prompt = PRESET_PROMPTS.get(preset) or str(body.get("message") or PRESET_PROMPTS["overview"])
        cfg = ai_store.load()
        if not cfg.is_ready():
            raise HTTPException(status_code=400, detail="AI 未配置完整")
        ctx = build_analysis_context(
            store,
            settings.data_dir,
            listening=server.listening_ports(),
            auth_mode=settings.effective_auth_mode.value,
        )
        messages = [
            {"role": "system", "content": cfg.system_prompt},
            {"role": "system", "content": context_as_prompt_block(ctx)},
            {"role": "user", "content": prompt},
        ]
        try:
            result = await chat_completion(cfg, messages)
        except AiClientError as e:
            raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e
        if result.get("provider"):
            cfg.detected_provider = str(result["provider"])
            ai_store.save(cfg)
        return {
            "content": result["content"],
            "model": result.get("model"),
            "preset": preset,
            "usage": result.get("usage"),
            "provider": result.get("provider"),
        }

    @app.get("/healthz")
    async def healthz() -> Any:
        """Unauthenticated liveness for systemd/load balancers — no secrets."""
        return {
            "status": "ok",
            "listening": len(server.listening_ports()),
            "version": __version__,
        }

    @app.get("/api/health")
    async def api_health(request: Request) -> Any:
        require_login(request)
        return {
            "status": "ok",
            "pipeline": pipeline.stats(),
            "limiter": limiter.snapshot(),
            "listening": server.listening_ports(),
            "last_auth": store.last_auth_ts(),
            "event_count": store.event_count(),
        }

    @app.get("/api/system")
    async def api_system(request: Request) -> Any:
        require_login(request)
        disk = disk_usage_report(settings.data_dir)
        return {
            "data_dir": str(settings.data_dir),
            "sqlite": str(settings.sqlite_path),
            "auth_mode": settings.effective_auth_mode.value,
            "disk": disk,
            "jsonl_files": disk.get("jsonl_files", []),
            "pipeline": pipeline.stats(),
            "limiter": limiter.snapshot(),
            "listening": server.listening_ports(),
            "retention": {
                "events_days": settings.events_retention_days,
                "jsonl_days": settings.jsonl_retention_days,
                "auth_stale_warn_hours": settings.auth_stale_warn_hours,
                "auto_export_hours": settings.auto_export_hours,
            },
            "event_count": store.event_count(),
            "last_auth": store.last_auth_ts(),
            "version": __version__,
        }

    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException) -> Any:
        if exc.status_code == 401 and request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=401)
        if exc.status_code == 401:
            return RedirectResponse("/login", status_code=302)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
