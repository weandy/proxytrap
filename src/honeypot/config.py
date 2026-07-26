from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from honeypot.models import AuthMode, PortConfig, Protocol


def _parse_protocol(value: str | Protocol) -> Protocol:
    if isinstance(value, Protocol):
        return value
    v = str(value).strip().lower()
    if v in ("socks5", "socks"):
        return Protocol.SOCKS5
    if v in ("http_proxy", "http", "https_proxy", "https"):
        return Protocol.HTTP_PROXY
    raise ValueError(f"unknown protocol: {value}")


class HttpDeception(BaseModel):
    server_header: str = "squid/5.8"
    realm: str = "Proxy Authentication Required"
    reject_status: int = 407


class Socks5Deception(BaseModel):
    prefer_userpass: bool = True
    connect_reply: str = "connection_refused"


class DeceptionConfig(BaseModel):
    auth_mode: AuthMode = AuthMode.ALWAYS_FAIL
    http: HttpDeception = Field(default_factory=HttpDeception)
    socks5: Socks5Deception = Field(default_factory=Socks5Deception)


class YamlFileConfig(BaseModel):
    deception: DeceptionConfig = Field(default_factory=DeceptionConfig)
    ports: list[PortConfig] = Field(default_factory=list)

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, value: Any) -> list[PortConfig]:
        if not value:
            return []
        out: list[PortConfig] = []
        for item in value:
            if isinstance(item, PortConfig):
                out.append(item)
                continue
            primary = _parse_protocol(item.get("primary", "http_proxy"))
            also_raw = item.get("also_accept") or []
            also = [_parse_protocol(x) for x in also_raw]
            out.append(
                PortConfig(
                    port=int(item["port"]),
                    primary=primary,
                    also_accept=also,
                    enabled=bool(item.get("enabled", True)),
                    note=str(item.get("note") or ""),
                )
            )
        return out


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Allow both field names (tests/programmatic) and ENV aliases (AUTH_MODE, DATA_DIR, …)
        populate_by_name=True,
    )

    data_dir: Path = Field(default=Path("./data"), validation_alias="DATA_DIR")
    config_path: Path = Field(
        default=Path("./config/config.example.yaml"),
        validation_alias="CONFIG_PATH",
    )
    honeypot_bind: str = Field(default="0.0.0.0", validation_alias="HONEYPOT_BIND")
    auth_mode: AuthMode | None = Field(default=None, validation_alias="AUTH_MODE")

    max_conns_global: int = Field(default=5000, validation_alias="MAX_CONNS_GLOBAL")
    max_conns_per_ip: int = Field(default=50, validation_alias="MAX_CONNS_PER_IP")
    read_timeout_sec: float = Field(default=10.0, validation_alias="READ_TIMEOUT_SEC")
    queue_maxsize: int = Field(default=10000, validation_alias="QUEUE_MAXSIZE")

    web_enabled: bool = Field(default=True, validation_alias="WEB_ENABLED")
    web_bind: str = Field(default="0.0.0.0:8787", validation_alias="WEB_BIND")
    web_auth_user: str = Field(default="admin", validation_alias="WEB_AUTH_USER")
    web_password: str = Field(default="", validation_alias="WEB_PASSWORD")
    web_session_secret: str = Field(default="", validation_alias="WEB_SESSION_SECRET")
    web_login_max_failures: int = Field(default=5, validation_alias="WEB_LOGIN_MAX_FAILURES")
    web_login_ban_minutes: int = Field(default=15, validation_alias="WEB_LOGIN_BAN_MINUTES")

    log_level: str = Field(default="info", validation_alias="LOG_LEVEL")

    # Filled after load_yaml
    yaml_config: YamlFileConfig = Field(default_factory=YamlFileConfig)

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "exports").mkdir(parents=True, exist_ok=True)

    @property
    def sqlite_path(self) -> Path:
        return self.data_dir / "honeypot.db"

    @property
    def effective_auth_mode(self) -> AuthMode:
        if self.auth_mode is not None:
            return self.auth_mode
        return self.yaml_config.deception.auth_mode

    def web_host_port(self) -> tuple[str, int]:
        raw = self.web_bind.strip()
        if raw.startswith("["):
            # [ipv6]:port
            host, _, port_s = raw[1:].partition("]:")
            return host, int(port_s)
        if raw.count(":") == 1:
            host, port_s = raw.split(":")
            return host or "0.0.0.0", int(port_s)
        return raw, 8787


def load_yaml_config(path: Path) -> YamlFileConfig:
    if not path.exists():
        return YamlFileConfig()
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return YamlFileConfig.model_validate(data)


def load_settings() -> Settings:
    settings = Settings()
    settings.yaml_config = load_yaml_config(settings.config_path)
    # Env AUTH_MODE overrides yaml deception.auth_mode when set
    if os.environ.get("AUTH_MODE"):
        settings.auth_mode = AuthMode(os.environ["AUTH_MODE"].strip().lower())
    settings.ensure_dirs()
    return settings
