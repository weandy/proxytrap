"""Build compact honeypot snapshots for LLM context."""

from __future__ import annotations

import json
from typing import Any

from honeypot.ops import disk_usage_report
from honeypot.sink.sqlite_store import SqliteStore


def build_analysis_context(
    store: SqliteStore,
    data_dir,
    *,
    top_creds: int = 30,
    top_sources: int = 20,
    recent_auth: int = 30,
    listening: list[int] | None = None,
    auth_mode: str | None = None,
) -> dict[str, Any]:
    summary_all = store.summary_stats()
    from datetime import datetime, timedelta, timezone

    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    summary_24h = store.summary_stats(day_ago)
    creds = store.top_credentials(top_creds)
    # strip bulky ip maps if any
    slim_creds = [
        {
            "user": c.get("username"),
            "pass": c.get("password"),
            "hits": c.get("hit_count"),
            "ports": c.get("ports_json"),
            "protocols": c.get("protocols_json"),
            "first": c.get("first_seen"),
            "last": c.get("last_seen"),
        }
        for c in creds
    ]
    sources = store.list_sources(top_sources)
    slim_sources = [
        {
            "ip": s.get("src_ip"),
            "conns": s.get("conn_count"),
            "auths": s.get("auth_count"),
            "ports": s.get("ports_json"),
            "protocols": s.get("protocols_json"),
            "last_user": s.get("last_username"),
            "last_pass": s.get("last_password"),
            "last_seen": s.get("last_seen"),
        }
        for s in sources
    ]
    events = store.recent_events(recent_auth, event_type="auth")
    slim_events = [
        {
            "ts": e.get("ts"),
            "ip": e.get("src_ip"),
            "port": e.get("dst_port"),
            "proto": e.get("detected_protocol"),
            "user": e.get("username"),
            "pass": e.get("password"),
        }
        for e in events
    ]
    disk = disk_usage_report(data_dir)
    return {
        "auth_mode": auth_mode,
        "listening_ports": listening or [],
        "summary_all_time": summary_all,
        "summary_24h": summary_24h,
        "top_credentials": slim_creds,
        "top_sources": slim_sources,
        "recent_auth_events": slim_events,
        "disk": {
            "data_human": disk.get("data_dir_human"),
            "raw_human": disk.get("raw_human"),
            "sqlite_human": disk.get("sqlite_human"),
            "jsonl_files": disk.get("jsonl_file_count"),
        },
        "last_auth_ts": store.last_auth_ts(),
        "event_count": store.event_count(),
    }


def context_as_prompt_block(ctx: dict[str, Any], max_chars: int = 24000) -> str:
    text = json.dumps(ctx, ensure_ascii=False, indent=2)
    if len(text) > max_chars:
        text = text[: max_chars - 20] + "\n...[truncated]"
    return (
        "以下是当前蜜罐采集数据快照（JSON）。请仅依据此数据分析。\n"
        f"```json\n{text}\n```"
    )


PRESET_PROMPTS = {
    "overview": "请对当前蜜罐数据做总览：攻击强度、主要来源、最常见账密、异常端口，并给出 3 条运维建议。",
    "password_book": "请评估已采集密码本的价值：高频组合、按端口/协议差异、是否值得合并进字典，输出可直接用的 top 建议列表。",
    "scanner_profile": "请根据 sources 与多端口行为，区分扫描器 vs 定点爆破，并标注可疑 IP 特征。",
    "risk": "从安全运营角度，当前暴露面与数据规模是否健康？有无存储/封禁/被云厂商误判风险？",
}
