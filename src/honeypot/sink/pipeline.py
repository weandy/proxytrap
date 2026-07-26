from __future__ import annotations

import asyncio
import logging
from typing import Any

from honeypot.models import HoneypotEvent
from honeypot.sink.jsonl import JsonlSink
from honeypot.sink.sqlite_store import SqliteStore

log = logging.getLogger(__name__)


class EventPipeline:
    """Async queue: handlers emit events; writer persists JSONL + SQLite.

    start() may be called before a loop exists (e.g. sync TestClient setup);
    the worker is then started lazily on the first emit() inside a running loop.
    """

    def __init__(self, jsonl: JsonlSink, store: SqliteStore, maxsize: int = 10000) -> None:
        self.jsonl = jsonl
        self.store = store
        self._maxsize = maxsize
        self.queue: asyncio.Queue[HoneypotEvent | None] | None = None
        self.dropped = 0
        self.written = 0
        self._task: asyncio.Task[Any] | None = None
        self._want_start = False
        self._closed = False

    def start(self) -> None:
        """Request pipeline start; binds to a running loop when available."""
        self._want_start = True
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._ensure_worker(loop)

    def _ensure_worker(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._closed:
            return
        if self.queue is None:
            self.queue = asyncio.Queue(maxsize=self._maxsize)
        if self._task is None or self._task.done():
            self._task = loop.create_task(self._worker(), name="event-pipeline")

    async def stop(self) -> None:
        self._closed = True
        if self.queue is None:
            self.jsonl.close()
            return
        await self.queue.put(None)
        if self._task:
            await self._task
            self._task = None
        self.jsonl.close()

    async def emit(self, event: HoneypotEvent) -> None:
        if self._closed:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No loop: persist synchronously (tests / edge)
            try:
                self._persist(event)
                self.written += 1
            except Exception:
                log.exception("sync persist failed")
            return

        if self._want_start or self.queue is None:
            self._ensure_worker(loop)

        assert self.queue is not None
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            if event.event_type == "auth":
                log.warning("event queue full, dropped auth event from %s", event.src_ip)

    async def _worker(self) -> None:
        assert self.queue is not None
        while True:
            item = await self.queue.get()
            try:
                if item is None:
                    return
                await asyncio.to_thread(self._persist, item)
                self.written += 1
            except Exception:
                log.exception("failed to persist event")
            finally:
                self.queue.task_done()

    def _persist(self, event: HoneypotEvent) -> None:
        self.jsonl.write(event)
        self.store.write_event(event)

    def stats(self) -> dict[str, int]:
        qsize = self.queue.qsize() if self.queue is not None else 0
        return {
            "queue_size": qsize,
            "written": self.written,
            "dropped": self.dropped,
        }
