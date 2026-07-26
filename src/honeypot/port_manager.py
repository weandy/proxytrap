from __future__ import annotations

import logging

from honeypot.models import PortConfig, Protocol
from honeypot.server import HoneypotServer
from honeypot.sink.sqlite_store import SqliteStore

log = logging.getLogger(__name__)


class PortManager:
    """Merge YAML ports + SQLite runtime ports; control live listeners."""

    def __init__(self, server: HoneypotServer, store: SqliteStore) -> None:
        self.server = server
        self.store = store

    def seed_from_config(self, ports: list[PortConfig]) -> None:
        for cfg in ports:
            # Runtime DB wins if already present with source=runtime
            existing = self.store.get_port(cfg.port)
            if existing and self._is_runtime(cfg.port):
                continue
            self.store.upsert_port(cfg, source="config")

    def _is_runtime(self, port: int) -> bool:
        rows = self.store.query("SELECT source FROM ports WHERE port=?", (port,))
        return bool(rows) and rows[0]["source"] == "runtime"

    async def start_all_enabled(self) -> list[str]:
        configs = [c for c in self.store.list_ports() if c.enabled]
        return await self.server.start_ports(configs)

    async def add_port(
        self,
        port: int,
        primary: str = "http_proxy",
        also_accept: list[str] | None = None,
        note: str = "",
        enable: bool = True,
    ) -> PortConfig:
        if port < 1 or port > 65535:
            raise ValueError("port out of range")
        primary_p = Protocol.SOCKS5 if primary in ("socks5", "socks") else Protocol.HTTP_PROXY
        also = []
        for a in also_accept or []:
            also.append(Protocol.SOCKS5 if a in ("socks5", "socks") else Protocol.HTTP_PROXY)
        if not also:
            # sensible default dual-stack
            also = (
                [Protocol.HTTP_PROXY]
                if primary_p == Protocol.SOCKS5
                else [Protocol.SOCKS5]
            )
        cfg = PortConfig(
            port=port,
            primary=primary_p,
            also_accept=also,
            enabled=enable,
            note=note,
        )
        self.store.upsert_port(cfg, source="runtime")
        if enable:
            await self.server.start_port(cfg)
        return cfg

    async def enable_port(self, port: int) -> PortConfig:
        cfg = self.store.get_port(port)
        if not cfg:
            raise KeyError(f"port {port} not found")
        cfg.enabled = True
        self.store.upsert_port(cfg, source="runtime")
        await self.server.start_port(cfg)
        return cfg

    async def disable_port(self, port: int) -> None:
        self.store.set_port_enabled(port, False)
        await self.server.stop_port(port)

    def list_with_status(self) -> list[dict]:
        db_ports = {p.port: p for p in self.store.list_ports()}
        listening = set(self.server.listening_ports())
        # ensure server cfgs reflected
        out = []
        for port, cfg in sorted(db_ports.items()):
            out.append(
                {
                    "port": port,
                    "primary": cfg.primary.value,
                    "also_accept": [x.value for x in cfg.also_accept],
                    "enabled": cfg.enabled,
                    "listening": port in listening,
                    "note": cfg.note,
                }
            )
        return out
