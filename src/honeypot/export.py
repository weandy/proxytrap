from __future__ import annotations

from pathlib import Path

from honeypot.sink.sqlite_store import SqliteStore


def export_top_credentials(
    store: SqliteStore,
    out_path: Path,
    limit: int = 1000,
    *,
    port: int | None = None,
    protocol: str | None = None,
) -> int:
    rows = store.top_credentials(limit, port=port, protocol=protocol)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in rows:
            user = r.get("username") or ""
            password = r.get("password") or ""
            hits = r.get("hit_count") or 0
            f.write(f"{user}:{password}\t{hits}\n")
    return len(rows)


def export_userpass_only(
    store: SqliteStore,
    out_path: Path,
    limit: int = 1000,
    *,
    port: int | None = None,
    protocol: str | None = None,
) -> int:
    rows = store.top_credentials(limit, port=port, protocol=protocol)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in rows:
            user = r.get("username") or ""
            password = r.get("password") or ""
            f.write(f"{user}:{password}\n")
    return len(rows)
