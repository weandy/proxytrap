"""Multi-compat AI client: OpenAI chat/completions, Responses API, Anthropic Messages."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from honeypot.ai_compat import (
    PROVIDER_ANTHROPIC,
    PROVIDER_AUTO,
    PROVIDER_OPENAI,
    PROVIDER_RESPONSES,
    anthropic_api_root,
    resolve_provider,
    smart_normalize_base,
)
from honeypot.ai_settings import AiSettings

log = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"


class AiClientError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def prepare_settings(settings: AiSettings) -> AiSettings:
    """Return a copy-like settings with smart-normalized base_url (mutates for convenience)."""
    norm = smart_normalize_base(settings.base_url, provider=settings.provider or PROVIDER_AUTO)
    settings.base_url = norm.base_url
    if settings.provider == PROVIDER_AUTO or not settings.provider:
        # keep auto in storage preference, but set detected if empty
        if not settings.detected_provider:
            settings.detected_provider = norm.provider_guess
    return settings


def _openai_headers(settings: AiSettings) -> dict[str, str]:
    h = {
        "Authorization": f"Bearer {settings.api_key.strip()}",
        "Content-Type": "application/json",
    }
    for k, v in (settings.extra_headers or {}).items():
        if k and v is not None:
            h[str(k)] = str(v)
    return h


def _anthropic_headers(settings: AiSettings) -> dict[str, str]:
    h = {
        "x-api-key": settings.api_key.strip(),
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    # Also send Authorization for gateways that rewrite
    h["Authorization"] = f"Bearer {settings.api_key.strip()}"
    for k, v in (settings.extra_headers or {}).items():
        if k and v is not None:
            h[str(k)] = str(v)
    return h


def _parse_model_list(data: Any) -> list[dict[str, Any]]:
    items = None
    if isinstance(data, dict):
        items = data.get("data") or data.get("models")
    elif isinstance(data, list):
        items = data
    if not isinstance(items, list):
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


async def _try_openai_models(client: httpx.AsyncClient, base: str, settings: AiSettings) -> list[dict[str, Any]]:
    url = f"{base.rstrip('/')}/models"
    resp = await client.get(url, headers=_openai_headers(settings))
    if resp.status_code >= 400:
        raise AiClientError(f"openai models HTTP {resp.status_code}: {resp.text[:400]}", resp.status_code)
    return _parse_model_list(resp.json())


async def _try_anthropic_models(client: httpx.AsyncClient, base: str, settings: AiSettings) -> list[dict[str, Any]]:
    root = anthropic_api_root(base)
    url = f"{root}/v1/models"
    resp = await client.get(url, headers=_anthropic_headers(settings))
    if resp.status_code >= 400:
        raise AiClientError(f"anthropic models HTTP {resp.status_code}: {resp.text[:400]}", resp.status_code)
    return _parse_model_list(resp.json())


async def fetch_models(
    settings: AiSettings,
    *,
    timeout: float = 30.0,
    probe: bool = True,
) -> dict[str, Any]:
    """
    Fetch models; auto-detect provider when needed.
    Returns {models, provider, base_url, notes}.
    """
    prepare_settings(settings)
    if not settings.normalized_base_url() or not settings.api_key.strip():
        raise AiClientError("base_url and api_key required")

    base = settings.normalized_base_url()
    preferred = resolve_provider(settings.provider, base, settings.model)
    notes: list[str] = []
    errors: list[str] = []

    order: list[str]
    if settings.provider and settings.provider != PROVIDER_AUTO:
        order = [settings.provider]
    elif preferred == PROVIDER_ANTHROPIC:
        order = [PROVIDER_ANTHROPIC, PROVIDER_OPENAI]
    else:
        # GPT-first then Claude
        order = [PROVIDER_OPENAI, PROVIDER_ANTHROPIC]

    async with httpx.AsyncClient(timeout=timeout) as client:
        for prov in order:
            try:
                if prov == PROVIDER_ANTHROPIC:
                    models = await _try_anthropic_models(client, base, settings)
                else:
                    models = await _try_openai_models(client, base, settings)
                    prov = PROVIDER_OPENAI
                settings.detected_provider = prov
                notes.append(f"models via {prov}")
                return {
                    "models": models,
                    "provider": prov,
                    "base_url": base,
                    "notes": notes,
                }
            except (AiClientError, httpx.RequestError) as e:
                errors.append(f"{prov}: {e}")
                log.info("model list probe failed for %s: %s", prov, e)
                if not probe:
                    break

    raise AiClientError("无法拉取模型，已尝试: " + " | ".join(errors) if errors else "models fetch failed")


def _split_system_messages(messages: list[dict[str, str]]) -> tuple[str, list[dict[str, str]]]:
    systems: list[str] = []
    rest: list[dict[str, str]] = []
    for m in messages:
        role = m.get("role") or "user"
        content = m.get("content") or ""
        if role == "system":
            systems.append(content)
        else:
            rest.append({"role": role, "content": content})
    return "\n\n".join(systems).strip(), rest


def _content_from_openai_chat(data: dict[str, Any]) -> str:
    try:
        content = data["choices"][0]["message"]["content"]
        if isinstance(content, list):
            # multimodal fragments
            parts = []
            for p in content:
                if isinstance(p, dict) and p.get("type") == "text":
                    parts.append(p.get("text") or "")
                elif isinstance(p, str):
                    parts.append(p)
            return "".join(parts)
        return content or ""
    except (KeyError, IndexError, TypeError):
        return str(data)[:4000]


def _content_from_responses(data: dict[str, Any]) -> str:
    # OpenAI Responses API shapes vary
    if isinstance(data.get("output_text"), str) and data["output_text"]:
        return data["output_text"]
    out = data.get("output")
    if isinstance(out, list):
        chunks: list[str] = []
        for item in out:
            if not isinstance(item, dict):
                continue
            for c in item.get("content") or []:
                if isinstance(c, dict) and c.get("type") in ("output_text", "text"):
                    chunks.append(c.get("text") or "")
        if chunks:
            return "".join(chunks)
    return _content_from_openai_chat(data) if "choices" in data else str(data)[:4000]


def _content_from_anthropic(data: dict[str, Any]) -> str:
    blocks = data.get("content") or []
    if isinstance(blocks, list):
        parts = []
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text") or "")
            elif isinstance(b, str):
                parts.append(b)
        return "".join(parts)
    return str(data)[:4000]


async def _chat_openai(
    client: httpx.AsyncClient,
    settings: AiSettings,
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    base = settings.normalized_base_url()
    url = f"{base}/chat/completions"
    payload = {
        "model": settings.model,
        "messages": messages,
        "temperature": settings.temperature,
    }
    resp = await client.post(url, headers=_openai_headers(settings), json=payload)
    if resp.status_code >= 400:
        raise AiClientError(f"chat HTTP {resp.status_code}: {resp.text[:800]}", resp.status_code)
    data = resp.json()
    return {
        "content": _content_from_openai_chat(data),
        "model": data.get("model") or settings.model,
        "usage": data.get("usage"),
        "provider": PROVIDER_OPENAI,
        "raw": data,
    }


async def _chat_responses(
    client: httpx.AsyncClient,
    settings: AiSettings,
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    """OpenAI Responses API — used when preferred or as fallback."""
    base = settings.normalized_base_url()
    url = f"{base}/responses"
    system, rest = _split_system_messages(messages)
    # Prefer input as message list when possible
    payload: dict[str, Any] = {
        "model": settings.model,
        "temperature": settings.temperature,
        "input": rest if rest else [{"role": "user", "content": "hello"}],
    }
    if system:
        payload["instructions"] = system
    resp = await client.post(url, headers=_openai_headers(settings), json=payload)
    if resp.status_code >= 400:
        raise AiClientError(f"responses HTTP {resp.status_code}: {resp.text[:800]}", resp.status_code)
    data = resp.json()
    return {
        "content": _content_from_responses(data),
        "model": data.get("model") or settings.model,
        "usage": data.get("usage"),
        "provider": PROVIDER_RESPONSES,
        "raw": data,
    }


async def _chat_anthropic(
    client: httpx.AsyncClient,
    settings: AiSettings,
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    root = anthropic_api_root(settings.normalized_base_url())
    url = f"{root}/v1/messages"
    system, rest = _split_system_messages(messages)
    # Anthropic requires alternating user/assistant; merge consecutive same roles lightly
    cleaned: list[dict[str, str]] = []
    for m in rest:
        role = m["role"] if m["role"] in ("user", "assistant") else "user"
        if cleaned and cleaned[-1]["role"] == role:
            cleaned[-1]["content"] += "\n" + m["content"]
        else:
            cleaned.append({"role": role, "content": m["content"]})
    if not cleaned:
        cleaned = [{"role": "user", "content": "请根据上下文分析。"}]
    if cleaned[0]["role"] != "user":
        cleaned.insert(0, {"role": "user", "content": "继续。"})
    payload: dict[str, Any] = {
        "model": settings.model,
        "max_tokens": 4096,
        "temperature": settings.temperature,
        "messages": cleaned,
    }
    if system:
        payload["system"] = system
    resp = await client.post(url, headers=_anthropic_headers(settings), json=payload)
    if resp.status_code >= 400:
        raise AiClientError(f"anthropic HTTP {resp.status_code}: {resp.text[:800]}", resp.status_code)
    data = resp.json()
    return {
        "content": _content_from_anthropic(data),
        "model": data.get("model") or settings.model,
        "usage": data.get("usage"),
        "provider": PROVIDER_ANTHROPIC,
        "raw": data,
    }


async def chat_completion(
    settings: AiSettings,
    messages: list[dict[str, str]],
    *,
    timeout: float = 120.0,
) -> dict[str, Any]:
    prepare_settings(settings)
    if not settings.is_ready():
        raise AiClientError("AI not configured (enable + base_url + api_key + model)")

    base = settings.normalized_base_url()
    primary = resolve_provider(
        settings.detected_provider or settings.provider,
        base,
        settings.model,
    )
    # If user forced provider, honor it
    if settings.provider and settings.provider != PROVIDER_AUTO:
        primary = settings.provider

    # GPT-first chain with smart fallbacks
    if primary == PROVIDER_ANTHROPIC:
        chain = [PROVIDER_ANTHROPIC, PROVIDER_OPENAI, PROVIDER_RESPONSES]
    elif primary == PROVIDER_RESPONSES:
        chain = [PROVIDER_RESPONSES, PROVIDER_OPENAI]
    else:
        chain = [PROVIDER_OPENAI, PROVIDER_RESPONSES, PROVIDER_ANTHROPIC]

    errors: list[str] = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        for prov in chain:
            try:
                if prov == PROVIDER_ANTHROPIC:
                    result = await _chat_anthropic(client, settings, messages)
                elif prov == PROVIDER_RESPONSES:
                    result = await _chat_responses(client, settings, messages)
                else:
                    result = await _chat_openai(client, settings, messages)
                settings.detected_provider = result["provider"]
                return result
            except (AiClientError, httpx.RequestError) as e:
                errors.append(f"{prov}: {e}")
                log.info("chat via %s failed: %s", prov, e)
                continue

    raise AiClientError("对话失败，已尝试多协议: " + " | ".join(errors))


async def probe_and_annotate(settings: AiSettings) -> dict[str, Any]:
    """Normalize URL + optional model probe; return public probe info."""
    norm = smart_normalize_base(settings.base_url, provider=settings.provider or PROVIDER_AUTO)
    info: dict[str, Any] = {
        "base_url": norm.base_url,
        "provider_guess": norm.provider_guess,
        "notes": list(norm.notes),
        "resolved_provider": resolve_provider(settings.provider, norm.base_url, settings.model),
    }
    settings.base_url = norm.base_url
    if settings.api_key.strip():
        try:
            m = await fetch_models(settings, probe=True)
            info["provider_detected"] = m["provider"]
            info["model_count"] = m["count"] if "count" in m else len(m["models"])
            info["notes"].extend(m.get("notes") or [])
        except AiClientError as e:
            info["probe_error"] = str(e)
    return info
