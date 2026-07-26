from __future__ import annotations

import asyncio
import base64
import logging
import re
from typing import Awaitable, Callable

from honeypot.config import DeceptionConfig
from honeypot.models import AuthMode, EventType, HoneypotEvent, PortConfig, Protocol

log = logging.getLogger(__name__)

EmitFn = Callable[[HoneypotEvent], Awaitable[None]]

_HEADER_END = re.compile(rb"\r\n\r\n")


def parse_basic_proxy_auth(header_value: str) -> tuple[str | None, str | None, str]:
    """Return (username, password, scheme)."""
    parts = header_value.strip().split(None, 1)
    if not parts:
        return None, None, "empty"
    scheme = parts[0].lower()
    if scheme != "basic" or len(parts) < 2:
        return None, None, scheme
    try:
        raw = base64.b64decode(parts[1].strip()).decode("utf-8", errors="replace")
    except Exception:
        return None, None, "basic"
    if ":" in raw:
        user, _, password = raw.partition(":")
        return user, password, "basic"
    return raw, "", "basic"


async def handle_http_proxy(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    first_bytes: bytes,
    port_cfg: PortConfig,
    conn_id: str,
    src_ip: str,
    src_port: int,
    deception: DeceptionConfig,
    auth_mode: AuthMode,
    emit: EmitFn,
    read_timeout: float,
) -> None:
    """HTTP proxy honeypot: 407 + capture Proxy-Authorization. Never forwards."""
    buf = bytearray(first_bytes)

    try:
        # Read until headers end or limit
        while not _HEADER_END.search(bytes(buf)):
            if len(buf) > 65536:
                break
            chunk = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
            if not chunk:
                break
            buf.extend(chunk)

        data = bytes(buf)
        header_match = _HEADER_END.search(data)
        header_blob = data[: header_match.start()] if header_match else data
        text = header_blob.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        if not lines or not lines[0]:
            await emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=port_cfg.port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.HTTP_PROXY,
                    event_type=EventType.PROBE,
                    extra={"reason": "empty_request"},
                )
            )
            return

        request_line = lines[0]
        parts = request_line.split()
        method = parts[0].upper() if parts else ""
        target = parts[1] if len(parts) > 1 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.HTTP_PROXY,
                event_type=EventType.NEGOTIATE,
                http_method=method,
                http_target=target,
                extra={"is_connect": method == "CONNECT"},
            )
        )

        proxy_auth = headers.get("proxy-authorization")
        username = password = None
        scheme = None
        if proxy_auth:
            username, password, scheme = parse_basic_proxy_auth(proxy_auth)
            await emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=port_cfg.port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.HTTP_PROXY,
                    event_type=EventType.AUTH,
                    username=username,
                    password=password,
                    auth_scheme=scheme or "basic",
                    http_method=method,
                    http_target=target,
                    extra={"is_connect": method == "CONNECT", "raw_scheme": scheme},
                )
            )

        server = deception.http.server_header
        realm = deception.http.realm
        status = deception.http.reject_status

        def build_407() -> bytes:
            body = b"Proxy Authentication Required\n"
            hdr = (
                f"HTTP/1.1 {status} Proxy Authentication Required\r\n"
                f"Server: {server}\r\n"
                f'Proxy-Authenticate: Basic realm="{realm}"\r\n'
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            return hdr.encode("ascii", errors="replace") + body

        def build_fail_after_fake_auth() -> bytes:
            # L2: claim auth ok path is not given; for CONNECT return 503/502 without tunnel
            code = 503
            reason = "Service Unavailable"
            body = b"Upstream unavailable\n"
            hdr = (
                f"HTTP/1.1 {code} {reason}\r\n"
                f"Server: {server}\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            return hdr.encode("ascii", errors="replace") + body

        if auth_mode == AuthMode.ALWAYS_FAIL or not proxy_auth:
            writer.write(build_407())
            await writer.drain()
            return

        # L2 with credentials present: fail upstream, still no forward
        writer.write(build_fail_after_fake_auth())
        await writer.drain()

    except asyncio.TimeoutError:
        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.HTTP_PROXY,
                event_type=EventType.TIMEOUT,
            )
        )
    except (ConnectionError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception:
        log.exception("http proxy handler error conn=%s", conn_id)
        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.HTTP_PROXY,
                event_type=EventType.ERROR,
                extra={"reason": "exception"},
            )
        )
