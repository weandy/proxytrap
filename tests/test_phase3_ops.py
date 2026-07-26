"""Phase 3: reindex, retention, export filters, healthz, disk report."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from honeypot.config import Settings
from honeypot.export import export_userpass_only
from honeypot.limits import ConnectionLimiter
from honeypot.models import AuthMode, EventType, HoneypotEvent, Protocol
from honeypot.ops import disk_usage_report, purge_old_jsonl, run_retention
from honeypot.port_manager import PortManager
from honeypot.reindex import reindex_from_jsonl
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore
from honeypot.web.app import create_app


def _ev(**kw) -> HoneypotEvent:
    base = dict(
        conn_id="c1",
        src_ip="9.9.9.9",
        src_port=1,
        dst_port=1080,
        configured_primary=Protocol.SOCKS5,
        detected_protocol=Protocol.SOCKS5,
        event_type=EventType.AUTH,
        username="u",
        password="p",
        auth_scheme="socks5-userpass",
    )
    base.update(kw)
    return HoneypotEvent.create(**base)


def test_reindex_rebuilds_credentials(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    day = raw / "events-2026-01-01.jsonl"
    e1 = _ev(username="alice", password="a1", dst_port=1080)
    e2 = _ev(username="bob", password="b1", dst_port=3128, detected_protocol=Protocol.HTTP_PROXY)
    with day.open("w", encoding="utf-8") as f:
        f.write(json.dumps(e1.to_dict()) + "\n")
        f.write(json.dumps(e2.to_dict()) + "\n")

    store = SqliteStore(tmp_path / "t.db")
    # poison DB with different data then reindex
    store.write_event(_ev(username="garbage", password="x"))
    stats = reindex_from_jsonl(store, raw)
    assert stats["events"] == 2
    assert stats["auths"] == 2
    rows = store.top_credentials(10)
    names = {(r["username"], r["password"]) for r in rows}
    assert ("alice", "a1") in names
    assert ("bob", "b1") in names
    assert ("garbage", "x") not in names
    store.close()


def test_export_filter_by_port_and_protocol(tmp_path: Path):
    store = SqliteStore(tmp_path / "t.db")
    store.write_event(
        _ev(username="s5", password="1", dst_port=1080, detected_protocol=Protocol.SOCKS5)
    )
    store.write_event(
        _ev(
            username="hp",
            password="2",
            dst_port=3128,
            detected_protocol=Protocol.HTTP_PROXY,
            configured_primary=Protocol.HTTP_PROXY,
        )
    )
    out = tmp_path / "e.txt"
    n = export_userpass_only(store, out, limit=10, port=1080)
    text = out.read_text(encoding="utf-8")
    assert n == 1
    assert "s5:1" in text
    assert "hp:2" not in text

    n2 = export_userpass_only(store, out, limit=10, protocol="http_proxy")
    text2 = out.read_text(encoding="utf-8")
    assert n2 == 1
    assert "hp:2" in text2
    store.close()


def test_purge_old_jsonl(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    old_day = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    new_day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    old_p = raw / f"events-{old_day}.jsonl"
    new_p = raw / f"events-{new_day}.jsonl"
    old_p.write_text("{}\n", encoding="utf-8")
    new_p.write_text("{}\n", encoding="utf-8")
    deleted = purge_old_jsonl(raw, retention_days=7)
    assert deleted == 1
    assert not old_p.exists()
    assert new_p.exists()


def test_run_retention_events(tmp_path: Path):
    store = SqliteStore(tmp_path / "t.db")
    old = _ev(username="old", password="o")
    # force old timestamp
    old.ts = "2020-01-01T00:00:00.000Z"
    store.write_event(old)
    store.write_event(_ev(username="new", password="n"))
    stats = run_retention(
        store, tmp_path, events_retention_days=1, jsonl_retention_days=0
    )
    assert stats["events_deleted"] >= 1
    # credentials table not auto-pruned by event delete — only events row gone
    assert store.event_count() == 1
    store.close()


def test_disk_usage_report(tmp_path: Path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "events-2099-01-01.jsonl").write_text("x\n", encoding="utf-8")
    r = disk_usage_report(tmp_path)
    assert r["jsonl_file_count"] == 1
    assert r["data_dir_bytes"] >= 1
    assert "human" in r["raw_human"].lower() or "B" in r["raw_human"]


@pytest.mark.asyncio
async def test_healthz_no_auth(tmp_path: Path):
    settings = Settings(
        data_dir=tmp_path,
        config_path=tmp_path / "none.yaml",
        honeypot_bind="127.0.0.1",
        web_enabled=True,
        web_password="x",
        web_session_secret="y",
        auth_mode=AuthMode.ALWAYS_FAIL,
    )
    settings.ensure_dirs()
    store = SqliteStore(tmp_path / "t.db")
    pipeline = EventPipeline(JsonlSink(tmp_path / "raw"), store, maxsize=10)
    pipeline.start()
    limiter = ConnectionLimiter(10, 5)
    server = HoneypotServer(settings, pipeline, limiter)
    pm = PortManager(server, store)
    app = create_app(settings, store, pipeline, server, pm, limiter)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        r = await client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        r2 = await client.get("/api/health")
        assert r2.status_code == 401
    await pipeline.stop()
    store.close()
