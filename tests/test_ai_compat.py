"""URL smart completion + multi-provider client behavior."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from honeypot.ai_client import chat_completion, fetch_models
from honeypot.ai_compat import (
    PROVIDER_ANTHROPIC,
    PROVIDER_OPENAI,
    guess_provider_from_model,
    resolve_provider,
    smart_normalize_base,
)
from honeypot.ai_settings import AiSettings


def test_smart_normalize_openai_host_only():
    n = smart_normalize_base("api.openai.com")
    assert n.base_url == "https://api.openai.com/v1"
    assert n.provider_guess == PROVIDER_OPENAI


def test_smart_normalize_strips_chat_path():
    n = smart_normalize_base("https://proxy.example.com/v1/chat/completions")
    assert n.base_url == "https://proxy.example.com/v1"


def test_smart_normalize_anthropic():
    n = smart_normalize_base("api.anthropic.com")
    assert n.base_url == "https://api.anthropic.com"
    assert n.provider_guess == PROVIDER_ANTHROPIC


def test_smart_normalize_custom_appends_v1():
    n = smart_normalize_base("https://llm.mycorp.com")
    assert n.base_url == "https://llm.mycorp.com/v1"
    assert n.provider_guess == PROVIDER_OPENAI


def test_model_guess():
    assert guess_provider_from_model("claude-sonnet-4-20250514") == PROVIDER_ANTHROPIC
    assert guess_provider_from_model("gpt-4o-mini") == PROVIDER_OPENAI
    assert resolve_provider("auto", "https://x/v1", "claude-3-5-sonnet") == PROVIDER_ANTHROPIC


@pytest.mark.asyncio
async def test_fetch_models_openai_then_shape():
    cfg = AiSettings(
        enabled=True,
        base_url="https://api.example.com",  # will normalize to /v1
        api_key="k",
        model="m",
        provider="auto",
    )

    class R:
        def __init__(self, code, data):
            self.status_code = code
            self._data = data
            self.text = str(data)

        def json(self):
            return self._data

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, headers=None):
            assert "/v1/models" in url or url.endswith("/models")
            return R(200, {"data": [{"id": "gpt-4o-mini"}]})

        async def post(self, *a, **k):
            raise AssertionError("no post")

    with patch("honeypot.ai_client.httpx.AsyncClient", return_value=FakeClient()):
        out = await fetch_models(cfg)
    assert out["provider"] == PROVIDER_OPENAI
    assert out["models"][0]["id"] == "gpt-4o-mini"
    assert out["base_url"].endswith("/v1")


@pytest.mark.asyncio
async def test_chat_openai_primary():
    cfg = AiSettings(
        enabled=True,
        base_url="https://api.example.com/v1",
        api_key="k",
        model="gpt-4o-mini",
        provider="openai",
    )

    class R:
        status_code = 200
        text = "ok"

        def json(self):
            return {
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "你好"}}],
                "usage": {"total_tokens": 3},
            }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, headers=None, json=None):
            assert url.endswith("/chat/completions")
            return R()

        async def get(self, *a, **k):
            raise AssertionError("no get")

    with patch("honeypot.ai_client.httpx.AsyncClient", return_value=FakeClient()):
        out = await chat_completion(cfg, [{"role": "user", "content": "hi"}])
    assert out["content"] == "你好"
    assert out["provider"] == PROVIDER_OPENAI


@pytest.mark.asyncio
async def test_chat_falls_back_to_anthropic():
    cfg = AiSettings(
        enabled=True,
        base_url="https://api.anthropic.com",
        api_key="k",
        model="claude-3-5-sonnet-latest",
        provider="auto",
    )
    calls = []

    class R:
        def __init__(self, code, data):
            self.status_code = code
            self._data = data
            self.text = "err" if code >= 400 else "ok"

        def json(self):
            return self._data

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, headers=None, json=None):
            calls.append(url)
            if "chat/completions" in url or url.endswith("/responses"):
                return R(404, {"error": "no"})
            if url.endswith("/v1/messages"):
                return R(
                    200,
                    {
                        "model": "claude-3-5-sonnet-latest",
                        "content": [{"type": "text", "text": "claude-ok"}],
                    },
                )
            return R(500, {})

    with patch("honeypot.ai_client.httpx.AsyncClient", return_value=FakeClient()):
        out = await chat_completion(cfg, [{"role": "user", "content": "hi"}])
    assert out["content"] == "claude-ok"
    assert out["provider"] == PROVIDER_ANTHROPIC
