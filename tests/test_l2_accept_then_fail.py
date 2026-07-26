"""L2 accept_then_fail still captures creds and never tunnels."""

from __future__ import annotations

import asyncio
import socket

import pytest

from honeypot.config import Settings
from honeypot.limits import ConnectionLimiter
from honeypot.models import AuthMode, PortConfig, Protocol
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_socks5_l2_auth_ok_connect_fails(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        config_path=tmp_path / "none.yaml",
        honeypot_bind="127.0.0.1",
        web_enabled=False,
        read_timeout_sec=3,
        auth_mode=AuthMode.ACCEPT_THEN_FAIL,
    )
    settings.ensure_dirs()
    store = SqliteStore(tmp_path / "t.db")
    pipeline = EventPipeline(JsonlSink(tmp_path / "raw"), store, maxsize=100)
    pipeline.start()
    limiter = ConnectionLimiter(100, 50)
    server = HoneypotServer(settings, pipeline, limiter)
    port = _free_port()
    await server.start_port(
        PortConfig(port=port, primary=Protocol.SOCKS5, also_accept=[Protocol.HTTP_PROXY], enabled=True)
    )
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(bytes([0x05, 0x01, 0x02]))
        await writer.drain()
        assert await reader.readexactly(2) == bytes([0x05, 0x02])
        user, password = b"l2user", b"l2pass"
        writer.write(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        auth = await reader.readexactly(2)
        assert auth == bytes([0x01, 0x00])  # auth accepted (L2)
        # CONNECT to 1.2.3.4:80 — must fail without tunnel
        # VER CMD RSV ATYP IPv4 PORT
        req = bytes([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
        writer.write(req)
        await writer.drain()
        rep = await reader.readexactly(10)
        assert rep[0] == 0x05
        assert rep[1] != 0x00  # not success
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.3)
        rows = store.top_credentials(10)
        assert any(r["username"] == "l2user" and r["password"] == "l2pass" for r in rows)
    finally:
        await server.stop_all()
        await pipeline.stop()
        store.close()
