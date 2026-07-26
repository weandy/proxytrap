"""Web session auth + dynamic port manager against real app/server paths."""

from __future__ import annotations

import asyncio
import socket

import pytest
from httpx import ASGITransport, AsyncClient

from honeypot.config import Settings
from honeypot.limits import ConnectionLimiter
from honeypot.models import AuthMode
from honeypot.port_manager import PortManager
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore
from honeypot.web.app import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
async def harness(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        config_path=tmp_path / "none.yaml",
        honeypot_bind="127.0.0.1",
        web_enabled=True,
        web_auth_user="admin",
        web_password="test-secret-pass",
        web_session_secret="test-session-secret",
        auth_mode=AuthMode.ALWAYS_FAIL,
        read_timeout_sec=3,
    )
    settings.ensure_dirs()
    store = SqliteStore(tmp_path / "t.db")
    pipeline = EventPipeline(JsonlSink(tmp_path / "raw"), store, maxsize=100)
    pipeline.start()
    limiter = ConnectionLimiter(100, 50)
    server = HoneypotServer(settings, pipeline, limiter)
    pm = PortManager(server, store)
    app = create_app(settings, store, pipeline, server, pm, limiter)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield {
            "client": client,
            "store": store,
            "server": server,
            "pm": pm,
            "settings": settings,
        }
    await server.stop_all()
    await pipeline.stop()
    store.close()


@pytest.mark.asyncio
async def test_api_requires_login(harness):
    r = await harness["client"].get("/api/credentials")
    assert r.status_code == 401
    assert r.json()["detail"] == "login required"


@pytest.mark.asyncio
async def test_wrong_password_rejected(harness):
    r = await harness["client"].post(
        "/login",
        data={"username": "admin", "password": "wrong"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_then_protected_api(harness):
    client = harness["client"]
    r = await client.post(
        "/login",
        data={"username": "admin", "password": "test-secret-pass"},
    )
    # follow redirect or 302
    assert r.status_code in (200, 302)
    r2 = await client.get("/api/stats/summary")
    assert r2.status_code == 200
    body = r2.json()
    assert "all_time" in body
    assert "pipeline" in body


@pytest.mark.asyncio
async def test_dynamic_port_add_listens_and_disable(harness):
    client = harness["client"]
    server = harness["server"]
    pm = harness["pm"]

    await client.post(
        "/login",
        data={"username": "admin", "password": "test-secret-pass"},
    )
    port = _free_port()
    r = await client.post(
        "/api/ports",
        json={"port": port, "primary": "socks5", "enabled": True, "note": "e2e"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["port"] == port
    assert port in server.listening_ports()

    s = socket.socket()
    try:
        s.settimeout(1)
        s.connect(("127.0.0.1", port))
    finally:
        s.close()

    r2 = await client.post(f"/api/ports/{port}/disable")
    assert r2.status_code == 200
    assert port not in server.listening_ports()

    await pm.enable_port(port)
    assert port in server.listening_ports()
    await pm.disable_port(port)
    assert port not in server.listening_ports()
