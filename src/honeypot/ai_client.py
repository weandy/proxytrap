"""OpenAI-compatible chat + models list against a custom base URL."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from honeypot.ai_settings import AiSettings

log = logging.getLogger(__name__)


class AiClientError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _headers(settings: AiSettings) -> dict[str, str]:
    h = {
        "Authorization": f"Bearer {settings.api_key.strip()}",
        "Content-Type": "application/json",
    }
    for k, v in (settings.extra_headers or {}).items():
        if k and v is not None:
            h[str(k)] = str(v)
    return h


async def fetch_models(settings: AiSettings, *, timeout: float = 30.0) -> list[dict[str, Any]]:
    base = settings.normalized_base_url()
    if not base or not settings.api_key.strip():
        raise AiClientError("base_url and api_key required")
    url = f"{base}/models"
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url, headers=_headers(settings))
        except httpx.RequestError as e:
            raise AiClientError(f"request failed: {e}") from e
    if resp.status_code >= 400:
        raise AiClientError(
            f"models HTTP {resp.status_code}: {resp.text[:500]}",
            status_code=resp.status_code,
        )
    data = resp.json()
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        # some gateways return {models: [...]} or plain list of strings
        if isinstance(data, dict) and isinstance(data.get("models"), list):
            items = data["models"]
        else:
            raise AiClientError("unexpected models response shape")
    out: list[dict[str, Any]] = []
    for it in items:
        if isinstance(it, str):
            out.append({"id": it})
        elif isinstance(it, dict):
            mid = it.get("id") or it.get("name") or it.get("model")
            if mid:
                out.append({"id": str(mid), "owned_by": it.get("owned_by"), "raw": it})
    out.sort(key=lambda x: x["id"])
    return out


async def chat_completion(
    settings: AiSettings,
    messages: list[dict[str, str]],
    *,
    timeout: float = 120.0,
) -> dict[str, Any]:
    base = settings.normalized_base_url()
    if not settings.is_ready():
        raise AiClientError("AI not configured (enable + base_url + api_key + model)")
    url = f"{base}/chat/completions"
    payload = {
        "model": settings.model,
        "messages": messages,
        "temperature": settings.temperature,
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(url, headers=_headers(settings), json=payload)
        except httpx.RequestError as e:
            raise AiClientError(f"request failed: {e}") from e
    if resp.status_code >= 400:
        raise AiClientError(
            f"chat HTTP {resp.status_code}: {resp.text[:800]}",
            status_code=resp.status_code,
        )
    data = resp.json()
    # normalize content
    content = ""
    try:
        content = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        content = str(data)[:4000]
    return {
        "content": content,
        "model": data.get("model") or settings.model,
        "usage": data.get("usage"),
        "raw": data,
    }
