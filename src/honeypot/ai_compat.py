"""Smart base-URL completion + multi-provider detection (OpenAI / Claude)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

# provider ids
PROVIDER_AUTO = "auto"
PROVIDER_OPENAI = "openai"  # OpenAI + most GPT gateways: /v1/chat/completions
PROVIDER_ANTHROPIC = "anthropic"  # Claude Messages API
PROVIDER_RESPONSES = "openai_responses"  # OpenAI Responses API /v1/responses

KNOWN_OPENAI_HOSTS = {
    "api.openai.com",
    "openai.azure.com",
}
KNOWN_ANTHROPIC_HOSTS = {
    "api.anthropic.com",
}


@dataclass
class NormalizedEndpoint:
    base_url: str
    provider_guess: str  # openai | anthropic | auto
    notes: list[str]


def _ensure_scheme(url: str) -> str:
    u = url.strip()
    if not u:
        return u
    if u.startswith("//"):
        return "https:" + u
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        return "https://" + u
    return u


def _strip_known_suffixes(path: str) -> str:
    """Strip accidental full API paths so base is reusable."""
    p = path.rstrip("/") or ""
    suffixes = (
        "/chat/completions",
        "/completions",
        "/messages",
        "/responses",
        "/models",
    )
    lower = p.lower()
    for s in suffixes:
        if lower.endswith(s):
            p = p[: -len(s)]
            lower = p.lower()
    return p.rstrip("/") or ""


def guess_provider_from_url(url: str) -> str:
    raw = _ensure_scheme(url or "")
    if not raw:
        return PROVIDER_OPENAI
    try:
        host = (urlparse(raw).hostname or "").lower()
    except Exception:
        host = ""
    if "anthropic" in host or host in KNOWN_ANTHROPIC_HOSTS:
        return PROVIDER_ANTHROPIC
    if "claude" in (url or "").lower() and "anthropic" in (url or "").lower():
        return PROVIDER_ANTHROPIC
    if host in KNOWN_OPENAI_HOSTS or "openai" in host:
        return PROVIDER_OPENAI
    # Azure OpenAI often contains openai.azure.com
    if "azure" in host and "openai" in host:
        return PROVIDER_OPENAI
    return PROVIDER_AUTO


def guess_provider_from_model(model: str) -> str | None:
    m = (model or "").strip().lower()
    if not m:
        return None
    if m.startswith("claude") or "claude-" in m or m.startswith("anthropic"):
        return PROVIDER_ANTHROPIC
    if m.startswith("gpt-") or m.startswith("o1") or m.startswith("o3") or m.startswith("o4"):
        return PROVIDER_OPENAI
    if "chatgpt" in m or m.startswith("ft:gpt"):
        return PROVIDER_OPENAI
    return None


def smart_normalize_base(
    url: str,
    *,
    provider: str = PROVIDER_AUTO,
) -> NormalizedEndpoint:
    """
    Intelligently complete base URL.

    Examples:
      api.openai.com              → https://api.openai.com/v1  (openai)
      https://api.openai.com      → https://api.openai.com/v1
      api.anthropic.com           → https://api.anthropic.com  (anthropic root)
      https://proxy.example.com   → https://proxy.example.com/v1
      .../v1/chat/completions     → .../v1
    """
    notes: list[str] = []
    raw = (url or "").strip()
    if not raw:
        notes.append("empty → default OpenAI public API")
        return NormalizedEndpoint("https://api.openai.com/v1", PROVIDER_OPENAI, notes)

    raw = _ensure_scheme(raw)
    notes.append("ensured https scheme" if not url.strip().startswith("http") else "scheme ok")

    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    path = _strip_known_suffixes(parsed.path or "")

    # Force guess from host if provider auto
    host_guess = guess_provider_from_url(raw)
    effective_provider = provider if provider and provider != PROVIDER_AUTO else host_guess
    if effective_provider == PROVIDER_AUTO:
        # custom gateway: prefer OpenAI-compat (GPT chat/completions) — user said GPT primary
        effective_provider = PROVIDER_OPENAI
        notes.append("custom host → assume OpenAI-compatible /v1")

    if host in KNOWN_ANTHROPIC_HOSTS or effective_provider == PROVIDER_ANTHROPIC and "anthropic" in host:
        # Anthropic official: base is origin without requiring trailing /v1 in stored form
        # but both https://api.anthropic.com and .../v1 are accepted
        if path in ("", "/"):
            base_path = ""
        elif path.rstrip("/") == "/v1":
            base_path = ""  # store origin; client adds /v1/messages
            notes.append("stripped /v1 from anthropic base (client uses /v1/messages)")
        else:
            base_path = path
        base = urlunparse((parsed.scheme or "https", parsed.netloc, base_path, "", "", "")).rstrip("/")
        notes.append("anthropic-style base")
        return NormalizedEndpoint(base, PROVIDER_ANTHROPIC, notes)

    # OpenAI-compatible: ensure .../v1
    if not path or path == "/":
        base_path = "/v1"
        notes.append("appended /v1")
    elif path.rstrip("/").endswith("/v1"):
        base_path = path.rstrip("/")
    else:
        # e.g. /openai or /api → append /v1 if not present
        if "/v1" in path:
            base_path = path.rstrip("/")
        else:
            base_path = path.rstrip("/") + "/v1"
            notes.append(f"appended /v1 to path {path!r}")

    base = urlunparse((parsed.scheme or "https", parsed.netloc, base_path, "", "", "")).rstrip("/")
    prov = PROVIDER_OPENAI if effective_provider in (PROVIDER_OPENAI, PROVIDER_RESPONSES, PROVIDER_AUTO) else effective_provider
    if host in KNOWN_OPENAI_HOSTS:
        prov = PROVIDER_OPENAI
        notes.append("known OpenAI host")
    return NormalizedEndpoint(base, prov, notes)


def resolve_provider(settings_provider: str, base_url: str, model: str) -> str:
    """Pick concrete provider for a request."""
    p = (settings_provider or PROVIDER_AUTO).strip().lower()
    if p in (PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_RESPONSES):
        return p
    # auto
    by_model = guess_provider_from_model(model)
    if by_model:
        return by_model
    by_url = guess_provider_from_url(base_url)
    if by_url != PROVIDER_AUTO:
        return by_url
    return PROVIDER_OPENAI


def anthropic_api_root(base_url: str) -> str:
    """Return origin used to build /v1/messages (no trailing slash)."""
    b = (base_url or "").rstrip("/")
    if b.endswith("/v1"):
        return b[: -len("/v1")]
    return b
