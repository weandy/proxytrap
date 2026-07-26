import asyncio

import pytest

from honeypot.config import Settings
from honeypot.limits import ConnectionLimiter
from honeypot.models import AuthMode, PortConfig, Protocol
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore


@pytest.mark.asyncio
async def test_socks5_auth_captured(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        config_path=tmp_path / "none.yaml",
        honeypot_bind="127.0.0.1",
        web_enabled=False,
        read_timeout_sec=3,
        auth_mode=AuthMode.ALWAYS_FAIL,
    )
    settings.ensure_dirs()
    store = SqliteStore(tmp_path / "t.db")
    pipeline = EventPipeline(JsonlSink(tmp_path / "raw"), store, maxsize=100)
    pipeline.start()
    limiter = ConnectionLimiter(100, 50)
    server = HoneypotServer(settings, pipeline, limiter)
    # bind ephemeral
    cfg = PortConfig(port=0, primary=Protocol.SOCKS5, also_accept=[Protocol.HTTP_PROXY], enabled=True)
    # asyncio.start_server with port 0 — our start_port uses cfg.port; use high free port via OS
    # Pick a free port
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    free_port = sock.getsockname()[1]
    sock.close()
    cfg.port = free_port
    await server.start_port(cfg)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", free_port)
        # greeting: ver=5, 1 method user/pass
        writer.write(bytes([0x05, 0x01, 0x02]))
        await writer.drain()
        resp = await reader.readexactly(2)
        assert resp == bytes([0x05, 0x02])
        user = b"hunter"
        password = b"2k"
        writer.write(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        assert auth_resp[0] == 0x01
        assert auth_resp[1] == 0x01  # fail
        writer.close()
        await writer.wait_closed()

        # wait pipeline
        await asyncio.sleep(0.3)
        rows = store.top_credentials(10)
        assert any(r["username"] == "hunter" and r["password"] == "2k" for r in rows)
    finally:
        await server.stop_all()
        await pipeline.stop()
        store.close()


@pytest.mark.asyncio
async def test_http_basic_captured(tmp_path):
    import base64

    settings = Settings(
        data_dir=tmp_path,
        config_path=tmp_path / "none.yaml",
        honeypot_bind="127.0.0.1",
        web_enabled=False,
        read_timeout_sec=3,
        auth_mode=AuthMode.ALWAYS_FAIL,
    )
    settings.ensure_dirs()
    store = SqliteStore(tmp_path / "t.db")
    pipeline = EventPipeline(JsonlSink(tmp_path / "raw"), store, maxsize=100)
    pipeline.start()
    limiter = ConnectionLimiter(100, 50)
    server = HoneypotServer(settings, pipeline, limiter)
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    free_port = sock.getsockname()[1]
    sock.close()
    cfg = PortConfig(port=free_port, primary=Protocol.HTTP_PROXY, also_accept=[Protocol.SOCKS5], enabled=True)
    await server.start_port(cfg)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", free_port)
        token = base64.b64encode(b"u1:p1").decode()
        req = (
            f"CONNECT example.com:443 HTTP/1.1\r\n"
            f"Host: example.com:443\r\n"
            f"Proxy-Authorization: Basic {token}\r\n"
            f"\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=3)
        assert b"407" in data or b"Proxy" in data
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.3)
        rows = store.top_credentials(10)
        assert any(r["username"] == "u1" and r["password"] == "p1" for r in rows)
    finally:
        await server.stop_all()
        await pipeline.stop()
        store.close()
