from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from honeypot.config import DeceptionConfig, Settings
from honeypot.detect import detect_protocol, first_bytes_hex
from honeypot.limits import ConnectionLimiter
from honeypot.models import AuthMode, EventType, HoneypotEvent, PortConfig, Protocol, new_id
from honeypot.proto.http_proxy import handle_http_proxy
from honeypot.proto.socks5 import handle_socks5
from honeypot.sink.pipeline import EventPipeline

log = logging.getLogger(__name__)


class HoneypotServer:
    def __init__(
        self,
        settings: Settings,
        pipeline: EventPipeline,
        limiter: ConnectionLimiter,
    ) -> None:
        self.settings = settings
        self.pipeline = pipeline
        self.limiter = limiter
        self._servers: dict[int, asyncio.AbstractServer] = {}
        self._port_cfgs: dict[int, PortConfig] = {}
        self._lock = asyncio.Lock()

    @property
    def deception(self) -> DeceptionConfig:
        return self.settings.yaml_config.deception

    @property
    def auth_mode(self) -> AuthMode:
        return self.settings.effective_auth_mode

    def listening_ports(self) -> list[int]:
        return sorted(self._servers.keys())

    def get_runtime_status(self) -> list[dict]:
        out = []
        for port, cfg in sorted(self._port_cfgs.items(), key=lambda x: x[0]):
            out.append(
                {
                    "port": port,
                    "primary": cfg.primary.value,
                    "also_accept": [p.value for p in cfg.also_accept],
                    "enabled": cfg.enabled,
                    "listening": port in self._servers,
                    "note": cfg.note,
                }
            )
        return out

    async def start_port(self, cfg: PortConfig) -> None:
        async with self._lock:
            if not cfg.enabled:
                self._port_cfgs[cfg.port] = cfg
                return
            if cfg.port in self._servers:
                self._port_cfgs[cfg.port] = cfg
                return
            try:
                server = await asyncio.start_server(
                    lambda r, w, c=cfg: self._on_connection(r, w, c),
                    host=self.settings.honeypot_bind,
                    port=cfg.port,
                )
            except OSError as e:
                log.error("failed to bind port %s: %s", cfg.port, e)
                raise
            self._servers[cfg.port] = server
            self._port_cfgs[cfg.port] = cfg
            log.info(
                "listening %s:%s primary=%s also=%s",
                self.settings.honeypot_bind,
                cfg.port,
                cfg.primary.value,
                [p.value for p in cfg.also_accept],
            )

    async def stop_port(self, port: int) -> None:
        async with self._lock:
            server = self._servers.pop(port, None)
            if port in self._port_cfgs:
                self._port_cfgs[port].enabled = False
            if server is not None:
                server.close()
                await server.wait_closed()
                log.info("stopped port %s", port)

    async def start_ports(self, configs: list[PortConfig]) -> list[str]:
        errors: list[str] = []
        for cfg in configs:
            try:
                await self.start_port(cfg)
            except OSError as e:
                errors.append(f"{cfg.port}: {e}")
        return errors

    async def stop_all(self) -> None:
        ports = list(self._servers.keys())
        for p in ports:
            await self.stop_port(p)

    async def _on_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port_cfg: PortConfig,
    ) -> None:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"
        src_port = int(peer[1]) if peer and len(peer) > 1 else 0
        conn_id = new_id()
        dst_port = port_cfg.port

        allowed = await self.limiter.acquire(src_ip)
        if not allowed:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            await self.pipeline.emit(
                HoneypotEvent.create(
                    conn_id=conn_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    configured_primary=port_cfg.primary,
                    detected_protocol=Protocol.UNKNOWN,
                    event_type=EventType.CONNECT,
                )
            )

            try:
                first = await asyncio.wait_for(
                    reader.read(64),
                    timeout=self.settings.read_timeout_sec,
                )
            except asyncio.TimeoutError:
                await self.pipeline.emit(
                    HoneypotEvent.create(
                        conn_id=conn_id,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        configured_primary=port_cfg.primary,
                        detected_protocol=Protocol.UNKNOWN,
                        event_type=EventType.TIMEOUT,
                    )
                )
                return

            if not first:
                return

            detected = detect_protocol(first)
            fb_hex = first_bytes_hex(first)

            if detected == Protocol.UNKNOWN:
                await self.pipeline.emit(
                    HoneypotEvent.create(
                        conn_id=conn_id,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        configured_primary=port_cfg.primary,
                        detected_protocol=Protocol.UNKNOWN,
                        event_type=EventType.PROBE,
                        client_first_bytes_hex=fb_hex,
                    )
                )
                return

            if not port_cfg.accepts(detected):
                await self.pipeline.emit(
                    HoneypotEvent.create(
                        conn_id=conn_id,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        configured_primary=port_cfg.primary,
                        detected_protocol=detected,
                        event_type=EventType.REJECT,
                        client_first_bytes_hex=fb_hex,
                        extra={"reason": "protocol_not_accepted"},
                    )
                )
                return

            emit: Callable[[HoneypotEvent], Awaitable[None]] = self.pipeline.emit
            common = dict(
                first_bytes=first,
                port_cfg=port_cfg,
                conn_id=conn_id,
                src_ip=src_ip,
                src_port=src_port,
                deception=self.deception,
                auth_mode=self.auth_mode,
                emit=emit,
                read_timeout=self.settings.read_timeout_sec,
            )

            # Attach first bytes hex on first protocol event via probe-level already done;
            # handlers emit more detailed events.
            if detected == Protocol.SOCKS5:
                await handle_socks5(reader, writer, **common)
            elif detected == Protocol.HTTP_PROXY:
                await handle_http_proxy(reader, writer, **common)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await self.limiter.release(src_ip)
