"""AI settings persistence + OpenAI-compatible client (mocked) + API routes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from honeypot.ai_client import AiClientError, chat_completion, fetch_models
from honeypot.ai_context import build_analysis_context, context_as_prompt_block
from honeypot.ai_settings import AiSettings, AiSettingsStore
from honeypot.config import Settings
from honeypot.limits import ConnectionLimiter
from honeypot.models import AuthMode, EventType, HoneypotEvent, Protocol
from honeypot.port_manager import PortManager
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore
from honeypot.web.app import create_app


def test_ai_settings_roundtrip(tmp_path: Path):
    store = AiSettingsStore(tmp_path / "ai_settings.json")
    s = AiSettings(
        enabled=True,
        base_url="https://example.com/v1",
        api_key="sk-secret-key",
        model="gpt-test",
        temperature=0.2,
    )
    store.save(s)
    loaded = store.load()
    assert loaded.enabled is True
    assert loaded.api_key == "sk-secret-key"
    assert loaded.model == "gpt-test"
    pub = loaded.public_dict(mask_key=True)
    assert pub["api_key_set"] is True
    assert "sk-secret-key" not in pub["api_key"]
    assert pub["api_key"].endswith("key")

    # blank key keeps previous
    store.update_from_payload({"api_key": "", "model": "other"})
    assert store.load().api_key == "sk-secret-key"
    assert store.load().model == "other"

    # masked key keeps previous
    store.update_from_payload({"api_key": "***********-key"})
    assert store.load().api_key == "sk-secret-key"


@pytest.mark.asyncio
async def test_fetch_models_and_chat_mocked():
    cfg = AiSettings(
        enabled=True,
        base_url="https://api.example/v1",
        api_key="k",
        model="m1",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "m1"}, {"id": "m2"}]})
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(
                200,
                json={
                    "model": "m1",
                    "choices": [{"message": {"role": "assistant", "content": "分析完成"}}],
                    "usage": {"total_tokens": 10},
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    with patch("honeypot.ai_client.httpx.AsyncClient") as ac:
        ac.return_value.__aenter__ = AsyncMock(
            return_value=httpx.AsyncClient(transport=transport, base_url="https://api.example")
        )
        ac.return_value.__aexit__ = AsyncMock(return_value=None)
        # Simpler: call real client with mock transport via patch of post/get
    # Direct unit with custom client injection is heavy; use respx-free manual mock on methods:

    async def fake_get(url, headers=None):
        class R:
            status_code = 200

            def json(self):
                return {"data": [{"id": "alpha"}, {"id": "beta"}]}

            text = "ok"

        return R()

    async def fake_post(url, headers=None, json=None):
        class R:
            status_code = 200

            def json(self):
                return {
                    "model": "alpha",
                    "choices": [{"message": {"content": "hello"}}],
                    "usage": {},
                }

            text = "ok"

        return R()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        get = staticmethod(fake_get)
        post = staticmethod(fake_post)

    with patch("honeypot.ai_client.httpx.AsyncClient", return_value=FakeClient()):
        result = await fetch_models(cfg)
        assert [m["id"] for m in result["models"]] == ["alpha", "beta"]
        out = await chat_completion(cfg, [{"role": "user", "content": "hi"}])
        assert out["content"] == "hello"


def test_context_build(tmp_path: Path):
    store = SqliteStore(tmp_path / "t.db")
    store.write_event(
        HoneypotEvent.create(
            conn_id="c",
            src_ip="1.1.1.1",
            src_port=1,
            dst_port=1080,
            configured_primary=Protocol.SOCKS5,
            detected_protocol=Protocol.SOCKS5,
            event_type=EventType.AUTH,
            username="a",
            password="b",
        )
    )
    ctx = build_analysis_context(store, tmp_path, listening=[1080], auth_mode="always_fail")
    assert ctx["summary_all_time"]["auths"] >= 1
    block = context_as_prompt_block(ctx)
    assert "1.1.1.1" in block or "a" in block
    store.close()


@pytest.mark.asyncio
async def test_ai_api_requires_login_and_saves(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        config_path=tmp_path / "none.yaml",
        honeypot_bind="127.0.0.1",
        web_enabled=True,
        web_auth_user="admin",
        web_password="secret",
        web_session_secret="sess",
        auth_mode=AuthMode.ALWAYS_FAIL,
    )
    settings.ensure_dirs()
    store = SqliteStore(tmp_path / "t.db")
    pipeline = EventPipeline(JsonlSink(tmp_path / "raw"), store, maxsize=10)
    pipeline.start()
    limiter = ConnectionLimiter(10, 5)
    server = HoneypotServer(settings, pipeline, limiter)
    pm = PortManager(server, store)
    app = create_app(settings, store, pipeline, server, pm, limiter)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        r = await client.get("/api/ai/settings")
        assert r.status_code == 401
        await client.post("/login", data={"username": "admin", "password": "secret"})
        r2 = await client.post(
            "/api/ai/settings",
            json={
                "enabled": True,
                "base_url": "https://x/v1",
                "api_key": "sk-test-abc",
                "model": "demo",
                "temperature": 0.1,
            },
        )
        assert r2.status_code == 200, r2.text
        assert r2.json()["settings"]["ready"] is True
        assert (tmp_path / "ai_settings.json").exists()
        saved = (tmp_path / "ai_settings.json").read_text(encoding="utf-8")
        assert "sk-test-abc" in saved
        # masked in API
        assert "sk-test-abc" not in r2.json()["settings"]["api_key"]

        with patch("honeypot.web.app.fetch_models", new_callable=AsyncMock) as fm:
            fm.return_value = {
                "models": [{"id": "demo"}, {"id": "other"}],
                "provider": "openai",
                "base_url": "https://x/v1",
                "notes": ["models via openai"],
            }
            r3 = await client.post("/api/ai/models", json={})
            assert r3.status_code == 200
            assert r3.json()["count"] == 2
            assert r3.json()["provider"] == "openai"

        with patch("honeypot.web.app.chat_completion", new_callable=AsyncMock) as cc:
            cc.return_value = {
                "content": "ok-analysis",
                "model": "demo",
                "usage": {},
                "provider": "openai",
            }
            r4 = await client.post(
                "/api/ai/chat",
                json={"message": "总结一下", "include_data": True},
            )
            assert r4.status_code == 200
            assert r4.json()["content"] == "ok-analysis"
            assert cc.await_count == 1

    await pipeline.stop()
    store.close()
