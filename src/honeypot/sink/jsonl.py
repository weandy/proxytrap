from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from honeypot.models import HoneypotEvent


class JsonlSink:
    def __init__(self, raw_dir: Path) -> None:
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._current_day: str | None = None
        self._fh = None

    def _day(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _ensure_file(self) -> None:
        day = self._day()
        if self._current_day == day and self._fh is not None:
            return
        if self._fh is not None:
            self._fh.close()
        path = self.raw_dir / f"events-{day}.jsonl"
        self._fh = path.open("a", encoding="utf-8")
        self._current_day = day

    def write(self, event: HoneypotEvent) -> None:
        line = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._ensure_file()
            assert self._fh is not None
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
