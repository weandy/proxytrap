from __future__ import annotations

import argparse
import asyncio
import logging
import sys

import uvicorn

from honeypot import __version__
from honeypot.config import load_settings
from honeypot.export import export_top_credentials, export_userpass_only
from honeypot.limits import ConnectionLimiter
from honeypot.port_manager import PortManager
from honeypot.server import HoneypotServer
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.pipeline import EventPipeline
from honeypot.sink.sqlite_store import SqliteStore
from honeypot.web.app import create_app


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


async def run_service() -> None:
    settings = load_settings()
    setup_logging(settings.log_level)
    log = logging.getLogger("honeypot")

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

    log.info(
        "honeypot started auth_mode=%s listening=%s data_dir=%s",
        settings.effective_auth_mode.value,
        server.listening_ports(),
        settings.data_dir,
    )

    config = None
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
            # honeypot only: sleep forever
            await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down...")
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
    if args.format == "userpass":
        n = export_userpass_only(store, out, limit=args.top)
    else:
        n = export_top_credentials(store, out, limit=args.top)
    store.close()
    print(f"exported {n} credentials to {out}")
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
    exp.set_defaults(func=cmd_export)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    # output path as Path
    if getattr(args, "output", None):
        from pathlib import Path

        args.output = Path(args.output)
    code = args.func(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
