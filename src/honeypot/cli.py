from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import uvicorn

from honeypot import __version__
from honeypot.config import load_settings
from honeypot.export import export_top_credentials, export_userpass_only
from honeypot.limits import ConnectionLimiter
from honeypot.ops import auto_export_daily, disk_usage_report, maybe_warn_stale_auth, run_retention
from honeypot.port_manager import PortManager
from honeypot.reindex import reindex_from_jsonl
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore
from honeypot.web.app import create_app

log = logging.getLogger("honeypot")


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


async def _maintenance_loop(
    settings,
    store: SqliteStore,
    started_at: datetime,
) -> None:
    """Periodic retention, stale-auth warn, optional daily export."""
    interval = max(60.0, float(settings.maintenance_interval_sec))
    last_export_day: str | None = None
    # first run after a short delay so boot logs stay clean
    await asyncio.sleep(min(30.0, interval))
    while True:
        try:
            stats = run_retention(
                store,
                settings.data_dir,
                events_retention_days=settings.events_retention_days,
                jsonl_retention_days=settings.jsonl_retention_days,
            )
            if stats["events_deleted"] or stats["jsonl_deleted"]:
                log.info("retention %s", stats)
            maybe_warn_stale_auth(store, settings.auth_stale_warn_hours, started_at)
            if settings.auto_export_hours > 0:
                day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                # export once per UTC day (interval still gates checks)
                if last_export_day != day:
                    auto_export_daily(store, settings.data_dir / "exports")
                    last_export_day = day
        except Exception:
            log.exception("maintenance loop error")
        await asyncio.sleep(interval)


async def run_service() -> None:
    settings = load_settings()
    setup_logging(settings.log_level)

    if settings.web_enabled and not settings.web_password:
        log.warning("WEB_ENABLED but WEB_PASSWORD is empty — login will be rejected until set")

    store = SqliteStore(settings.sqlite_path)
    jsonl = JsonlSink(settings.data_dir / "raw")
    pipeline = EventPipeline(jsonl, store, maxsize=settings.queue_maxsize)
    pipeline.start()

    limiter = ConnectionLimiter(settings.max_conns_global, settings.max_conns_per_ip)
    server = HoneypotServer(settings, pipeline, limiter)
    port_manager = PortManager(server, store)
    port_manager.seed_from_config(settings.yaml_config.ports)
    errors = await port_manager.start_all_enabled()
    for e in errors:
        log.error("port start error: %s", e)

    started_at = datetime.now(timezone.utc)
    log.info(
        "honeypot started auth_mode=%s listening=%s data_dir=%s retention_events=%sd jsonl=%sd",
        settings.effective_auth_mode.value,
        server.listening_ports(),
        settings.data_dir,
        settings.events_retention_days,
        settings.jsonl_retention_days,
    )

    maint_task = asyncio.create_task(
        _maintenance_loop(settings, store, started_at),
        name="maintenance",
    )

    server_task = None
    if settings.web_enabled:
        app = create_app(settings, store, pipeline, server, port_manager, limiter)
        host, port = settings.web_host_port()
        config = uvicorn.Config(app, host=host, port=port, log_level=settings.log_level.lower())
        uv_server = uvicorn.Server(config)
        server_task = asyncio.create_task(uv_server.serve(), name="web")
        log.info("web listening on http://%s:%s", host, port)

    try:
        if server_task:
            await server_task
        else:
            await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down...")
        maint_task.cancel()
        try:
            await maint_task
        except asyncio.CancelledError:
            pass
        await server.stop_all()
        await pipeline.stop()
        store.close()


def cmd_run(_args: argparse.Namespace) -> int:
    try:
        asyncio.run(run_service())
    except KeyboardInterrupt:
        return 0
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    settings = load_settings()
    store = SqliteStore(settings.sqlite_path)
    out = args.output or (settings.data_dir / "exports" / "top_creds.txt")
    kwargs = {"limit": args.top, "port": args.port, "protocol": args.protocol}
    if args.format == "userpass":
        n = export_userpass_only(store, out, **kwargs)
    else:
        n = export_top_credentials(store, out, **kwargs)
    store.close()
    print(f"exported {n} credentials to {out}")
    return 0


def cmd_reindex(args: argparse.Namespace) -> int:
    settings = load_settings()
    setup_logging(settings.log_level)
    raw = Path(args.raw_dir) if args.raw_dir else (settings.data_dir / "raw")
    store = SqliteStore(settings.sqlite_path)
    stats = reindex_from_jsonl(store, raw)
    store.close()
    print(f"reindexed from {raw}: events={stats['events']} auths={stats['auths']}")
    return 0


def cmd_disk(_args: argparse.Namespace) -> int:
    settings = load_settings()
    report = disk_usage_report(settings.data_dir)
    for k, v in report.items():
        if k == "jsonl_files":
            continue
        print(f"{k}: {v}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="honeypot", description="SOCKS5/HTTP proxy auth honeypot")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Start honeypot (+ optional web)")
    run_p.set_defaults(func=cmd_run)

    exp = sub.add_parser("export", help="Export credential wordlist from SQLite")
    exp.add_argument("--top", type=int, default=1000)
    exp.add_argument("--output", "-o", type=str, default=None)
    exp.add_argument("--format", choices=("counted", "userpass"), default="counted")
    exp.add_argument("--port", type=int, default=None, help="Only creds seen on this port")
    exp.add_argument(
        "--protocol",
        type=str,
        default=None,
        help="Only creds seen on protocol (socks5|http_proxy)",
    )
    exp.set_defaults(func=cmd_export)

    re = sub.add_parser("reindex", help="Rebuild SQLite aggregates from JSONL")
    re.add_argument(
        "--raw-dir",
        type=str,
        default=None,
        help="JSONL directory (default: DATA_DIR/raw)",
    )
    re.set_defaults(func=cmd_reindex)

    disk = sub.add_parser("disk", help="Show data directory disk usage")
    disk.set_defaults(func=cmd_disk)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "output", None):
        args.output = Path(args.output)
    code = args.func(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
