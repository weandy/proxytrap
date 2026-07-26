from __future__ import annotations

import asyncio
import logging
from typing import Callable, Awaitable

from honeypot.config import DeceptionConfig
from honeypot.models import AuthMode, EventType, HoneypotEvent, PortConfig, Protocol

log = logging.getLogger(__name__)

EmitFn = Callable[[HoneypotEvent], Awaitable[None]]

# SOCKS5 reply codes for CONNECT (never succeeds as open proxy)
REP_GENERAL_FAILURE = 0x01
REP_CONN_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05


async def handle_socks5(
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
    """SOCKS5 honeypot: capture USER/PASS, never forward."""
    buf = bytearray(first_bytes)

    async def read_exact(n: int) -> bytes:
        while len(buf) < n:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
            if not chunk:
                raise ConnectionError("eof")
            buf.extend(chunk)
        data = bytes(buf[:n])
        del buf[:n]
        return data

    async def read_some() -> bytes:
        if buf:
            data = bytes(buf)
            buf.clear()
            return data
        return await asyncio.wait_for(reader.read(4096), timeout=read_timeout)

    try:
        # Need at least VER NMETHODS
        if len(buf) < 2:
            more = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
            if not more:
                return
            buf.extend(more)

        ver = buf[0]
        if ver != 0x05:
            await emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=port_cfg.port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.SOCKS5,
                    event_type=EventType.PROBE,
                    extra={"reason": "bad_version", "ver": ver},
                )
            )
            return

        nmethods = buf[1]
        greeting = await read_exact(2 + nmethods)
        methods = list(greeting[2:])

        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.SOCKS5,
                event_type=EventType.NEGOTIATE,
                extra={"methods": methods},
            )
        )

        prefer = deception.socks5.prefer_userpass
        if prefer and 0x02 in methods:
            writer.write(bytes([0x05, 0x02]))
            await writer.drain()
        elif 0x00 in methods and not prefer:
            # We still want credentials; reject no-auth preference path
            writer.write(bytes([0x05, 0xFF]))
            await writer.drain()
            await emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=port_cfg.port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.SOCKS5,
                    event_type=EventType.REJECT,
                    extra={"reason": "no_userpass_offered"},
                )
            )
            return
        elif 0x02 in methods:
            writer.write(bytes([0x05, 0x02]))
            await writer.drain()
        else:
            writer.write(bytes([0x05, 0xFF]))
            await writer.drain()
            await emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=port_cfg.port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.SOCKS5,
                    event_type=EventType.REJECT,
                    extra={"reason": "no_userpass_offered", "methods": methods},
                )
            )
            return

        # RFC1929 username/password
        auth_head = await read_exact(2)
        auth_ver, ulen = auth_head[0], auth_head[1]
        if auth_ver != 0x01:
            await emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=port_cfg.port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.SOCKS5,
                    event_type=EventType.ERROR,
                    extra={"reason": "bad_auth_ver", "ver": auth_ver},
                )
            )
            return
        uname = await read_exact(ulen)
        plen_b = await read_exact(1)
        plen = plen_b[0]
        passwd = await read_exact(plen)
        username = uname.decode("utf-8", errors="replace")
        password = passwd.decode("utf-8", errors="replace")

        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.SOCKS5,
                event_type=EventType.AUTH,
                username=username,
                password=password,
                auth_scheme="socks5-userpass",
            )
        )

        if auth_mode == AuthMode.ALWAYS_FAIL:
            writer.write(bytes([0x01, 0x01]))  # auth failure
            await writer.drain()
            return

        # L2: accept auth then fail CONNECT
        writer.write(bytes([0x01, 0x00]))
        await writer.drain()

        # Read request and reply failure — no dial
        req_head = await read_exact(4)
        # ver cmd rsv atyp
        atyp = req_head[3]
        if atyp == 0x01:
            await read_exact(4 + 2)
        elif atyp == 0x03:
            ln = (await read_exact(1))[0]
            await read_exact(ln + 2)
        elif atyp == 0x04:
            await read_exact(16 + 2)
        else:
            return

        rep = REP_CONNECTION_REFUSED
        if deception.socks5.connect_reply == "host_unreachable":
            rep = REP_HOST_UNREACHABLE
        elif deception.socks5.connect_reply == "general_failure":
            rep = REP_GENERAL_FAILURE
        # VER REP RSV ATYP BND.ADDR BND.PORT
        writer.write(bytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
    except asyncio.TimeoutError:
        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.SOCKS5,
                event_type=EventType.TIMEOUT,
            )
        )
    except (ConnectionError, asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        log.exception("socks5 handler error conn=%s", conn_id)
        await emit(
            HoneypotEvent.create(
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=port_cfg.port,
                configured_primary=port_cfg.primary,
                detected_protocol=Protocol.SOCKS5,
                event_type=EventType.ERROR,
                extra={"reason": "exception"},
            )
        )
