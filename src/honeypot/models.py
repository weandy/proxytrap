from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Protocol(str, Enum):
    SOCKS5 = "socks5"
    HTTP_PROXY = "http_proxy"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    CONNECT = "connect"
    PROBE = "probe"
    NEGOTIATE = "negotiate"
    AUTH = "auth"
    REJECT = "reject"
    TIMEOUT = "timeout"
    ERROR = "error"


class AuthMode(str, Enum):
    ALWAYS_FAIL = "always_fail"
    ACCEPT_THEN_FAIL = "accept_then_fail"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id() -> str:
    return uuid4().hex


@dataclass
class PortConfig:
    port: int
    primary: Protocol = Protocol.HTTP_PROXY
    also_accept: list[Protocol] = field(default_factory=list)
    enabled: bool = True
    note: str = ""

    def accepts(self, detected: Protocol) -> bool:
        if detected == Protocol.UNKNOWN:
            return False
        if detected == self.primary:
            return True
        return detected in self.also_accept


@dataclass
class HoneypotEvent:
    ts: str
    event_id: str
    conn_id: str
    src_ip: str
    src_port: int
    dst_port: int
    configured_primary: str
    detected_protocol: str
    event_type: str
    username: str | None = None
    password: str | None = None
    auth_scheme: str | None = None
    http_method: str | None = None
    http_target: str | None = None
    tls: bool = False
    client_first_bytes_hex: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        conn_id: str,
        src_ip: str,
        src_port: int,
        dst_port: int,
        configured_primary: Protocol | str,
        detected_protocol: Protocol | str,
        event_type: EventType | str,
        username: str | None = None,
        password: str | None = None,
        auth_scheme: str | None = None,
        http_method: str | None = None,
        http_target: str | None = None,
        tls: bool = False,
        client_first_bytes_hex: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> HoneypotEvent:
        primary = configured_primary.value if isinstance(configured_primary, Protocol) else configured_primary
        detected = detected_protocol.value if isinstance(detected_protocol, Protocol) else detected_protocol
        et = event_type.value if isinstance(event_type, EventType) else event_type
        return cls(
            ts=utc_now_iso(),
            event_id=new_id(),
            conn_id=conn_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            configured_primary=primary,
            detected_protocol=detected,
            event_type=et,
            username=username,
            password=password,
            auth_scheme=auth_scheme,
            http_method=http_method,
            http_target=http_target,
            tls=tls,
            client_first_bytes_hex=client_first_bytes_hex,
            extra=extra or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
