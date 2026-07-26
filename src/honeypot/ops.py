"""Phase-3 ops: disk stats, retention, stale-auth warnings, scheduled export."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from honeypot.export import export_userpass_only
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.sqlite_store import SqliteStore

log = logging.getLogger(__name__)


def dir_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def human_bytes(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(x)} {unit}"
            return f"{x:.1f} {unit}"
        x /= 1024
    return f"{n} B"


def disk_usage_report(data_dir: Path) -> dict:
    raw = data_dir / "raw"
    exports = data_dir / "exports"
    db = data_dir / "honeypot.db"
    raw_files = sorted(raw.glob("events-*.jsonl")) if raw.exists() else []
    return {
        "data_dir": str(data_dir),
        "data_dir_bytes": dir_size_bytes(data_dir),
        "data_dir_human": human_bytes(dir_size_bytes(data_dir)),
        "raw_bytes": dir_size_bytes(raw),
        "raw_human": human_bytes(dir_size_bytes(raw)),
        "exports_bytes": dir_size_bytes(exports),
        "exports_human": human_bytes(dir_size_bytes(exports)),
        "sqlite_bytes": dir_size_bytes(db) if db.exists() else 0,
        "sqlite_human": human_bytes(dir_size_bytes(db) if db.exists() else 0),
        "jsonl_file_count": len(raw_files),
        "jsonl_files": [p.name for p in raw_files[-30:]],
        "disk_free_bytes": shutil.disk_usage(str(data_dir if data_dir.exists() else Path("."))).free,
        "disk_free_human": human_bytes(
            shutil.disk_usage(str(data_dir if data_dir.exists() else Path("."))).free
        ),
    }


def purge_old_jsonl(raw_dir: Path, retention_days: int) -> int:
    """Delete events-YYYY-MM-DD.jsonl older than retention_days (UTC). Returns count deleted."""
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=retention_days)
    deleted = 0
    if not raw_dir.exists():
        return 0
    for path in raw_dir.glob("events-*.jsonl"):
        # events-2026-07-26.jsonl
        name = path.stem  # events-2026-07-26
        try:
            day_s = name.split("events-", 1)[1]
            day = datetime.strptime(day_s, "%Y-%m-%d").date()
        except (IndexError, ValueError):
            continue
        if day < cutoff:
            path.unlink(missing_ok=True)
            deleted += 1
            log.info("purged jsonl %s", path.name)
    return deleted


def purge_old_events(store: SqliteStore, retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    n = store.delete_events_before(cutoff)
    if n:
        log.info("purged %s event rows before %s", n, cutoff)
    return n


def maybe_warn_stale_auth(store: SqliteStore, warn_hours: float, started_at: datetime) -> bool:
    """Return True if a warning was emitted."""
    if warn_hours <= 0:
        return False
    uptime = datetime.now(timezone.utc) - started_at
    if uptime < timedelta(hours=warn_hours):
        return False
    last = store.last_auth_ts()
    if last is None:
        log.warning(
            "no auth events recorded in the last %.1fh (uptime=%.1fh) — check ports/security group",
            warn_hours,
            uptime.total_seconds() / 3600,
        )
        return True
    try:
        # tolerate Z suffix
        last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = datetime.now(timezone.utc) - last_dt.astimezone(timezone.utc)
    if age >= timedelta(hours=warn_hours):
        log.warning(
            "no auth events for %.1fh (last_auth=%s) — check exposure / filters",
            age.total_seconds() / 3600,
            last,
        )
        return True
    return False


def auto_export_daily(store: SqliteStore, exports_dir: Path, limit: int = 5000) -> Path | None:
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = exports_dir / f"daily-{day}.txt"
    export_userpass_only(store, out, limit=limit)
    log.info("auto-exported credentials to %s", out)
    return out


def run_retention(
    store: SqliteStore,
    data_dir: Path,
    *,
    events_retention_days: int,
    jsonl_retention_days: int,
) -> dict[str, int]:
    ev = purge_old_events(store, events_retention_days)
    jl = purge_old_jsonl(data_dir / "raw", jsonl_retention_days)
    return {"events_deleted": ev, "jsonl_deleted": jl}
