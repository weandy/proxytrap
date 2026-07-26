"""Rebuild SQLite analytics tables from JSONL (source of truth)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from honeypot.models import HoneypotEvent
from honeypot.sink.sqlite_store import SqliteStore

log = logging.getLogger(__name__)


def iter_jsonl_events(raw_dir: Path):
    if not raw_dir.exists():
        return
    for path in sorted(raw_dir.glob("events-*.jsonl")):
        with path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    yield HoneypotEvent.from_dict(data)
                except Exception:
                    log.warning("skip bad jsonl %s:%s", path.name, lineno)


def reindex_from_jsonl(store: SqliteStore, raw_dir: Path) -> dict[str, int]:
    """
    Clear event-derived tables and re-ingest all JSONL lines via write_event.
    Preserves runtime/config ports table.
    """
    store.clear_analytics()
    n = 0
    auth_n = 0
    for event in iter_jsonl_events(raw_dir):
        store.write_event(event)
        n += 1
        if event.event_type == "auth":
            auth_n += 1
    return {"events": n, "auths": auth_n}
