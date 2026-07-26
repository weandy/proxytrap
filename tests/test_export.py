"""Export wordlist from real SQLite store after auth capture."""

from __future__ import annotations

import asyncio
import base64
import socket

import pytest

from honeypot.config import Settings
from honeypot.export import export_userpass_only
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
async def test_export_contains_captured_http_creds(tmp_path):
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
    port = _free_port()
    await server.start_port(
        PortConfig(port=port, primary=Protocol.HTTP_PROXY, also_accept=[Protocol.SOCKS5], enabled=True)
    )
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        token = base64.b64encode(b"export_user:export_pass").decode()
        req = (
            f"GET http://example.com/ HTTP/1.1\r\n"
            f"Host: example.com\r\n"
            f"Proxy-Authorization: Basic {token}\r\n"
            f"\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=3)
        assert b"407" in data
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.3)

        out = tmp_path / "exports" / "wl.txt"
        n = export_userpass_only(store, out, limit=100)
        assert n >= 1
        text = out.read_text(encoding="utf-8")
        assert "export_user:export_pass" in text
    finally:
        await server.stop_all()
        await pipeline.stop()
        store.close()
