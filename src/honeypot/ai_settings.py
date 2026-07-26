"""Persist AI provider settings outside .env (data_dir/ai_settings.json)."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock

log = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = (
    "你是代理蜜罐（proxy auth honeypot）数据分析助手。"
    "用户部署的是永不转发的 SOCKS5/HTTP 认证蜜罐，用于采集扫描与爆破账密。"
    "请基于提供的数据给出：威胁画像、密码本质量、端口差异、是否扫描器、"
    "运维建议。回答简洁、可执行，使用中文。不要编造数据中不存在的数字。"
)


@dataclass
class AiSettings:
    enabled: bool = False
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = ""
    temperature: float = 0.3
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    # optional extra headers as list of {name,value} for non-standard gateways
    extra_headers: dict[str, str] = field(default_factory=dict)

    def normalized_base_url(self) -> str:
        return (self.base_url or "").strip().rstrip("/")

    def is_ready(self) -> bool:
        return bool(
            self.enabled
            and self.normalized_base_url()
            and self.api_key.strip()
            and self.model.strip()
        )

    def public_dict(self, *, mask_key: bool = True) -> dict:
        key = self.api_key or ""
        if mask_key and key:
            shown = ("*" * max(0, len(key) - 4)) + key[-4:]
        else:
            shown = key
        return {
            "enabled": self.enabled,
            "base_url": self.base_url,
            "api_key": shown,
            "api_key_set": bool(key),
            "model": self.model,
            "temperature": self.temperature,
            "system_prompt": self.system_prompt,
            "extra_headers": self.extra_headers,
            "ready": self.is_ready(),
        }


class AiSettingsStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()

    def load(self) -> AiSettings:
        with self._lock:
            if not self.path.exists():
                return AiSettings()
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                log.exception("failed to read AI settings %s", self.path)
                return AiSettings()
            return AiSettings(
                enabled=bool(data.get("enabled", False)),
                base_url=str(data.get("base_url") or "https://api.openai.com/v1"),
                api_key=str(data.get("api_key") or ""),
                model=str(data.get("model") or ""),
                temperature=float(data.get("temperature") if data.get("temperature") is not None else 0.3),
                system_prompt=str(data.get("system_prompt") or DEFAULT_SYSTEM_PROMPT),
                extra_headers=dict(data.get("extra_headers") or {}),
            )

    def save(self, settings: AiSettings) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            payload = asdict(settings)
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def update_from_payload(self, body: dict, *, keep_key_if_blank: bool = True) -> AiSettings:
        current = self.load()
        if "enabled" in body:
            current.enabled = bool(body["enabled"])
        if "base_url" in body and body["base_url"] is not None:
            current.base_url = str(body["base_url"]).strip()
        if "api_key" in body and body["api_key"] is not None:
            new_key = str(body["api_key"]).strip()
            if not new_key:
                if not keep_key_if_blank:
                    current.api_key = ""
                # else keep existing key
            elif new_key.startswith("*") and current.api_key:
                # masked display value posted back — keep existing
                pass
            else:
                current.api_key = new_key
        if "model" in body and body["model"] is not None:
            current.model = str(body["model"]).strip()
        if "temperature" in body and body["temperature"] is not None:
            try:
                current.temperature = float(body["temperature"])
            except (TypeError, ValueError):
                pass
        if "system_prompt" in body and body["system_prompt"] is not None:
            current.system_prompt = str(body["system_prompt"])
        if "extra_headers" in body and isinstance(body["extra_headers"], dict):
            current.extra_headers = {str(k): str(v) for k, v in body["extra_headers"].items()}
        self.save(current)
        return current
