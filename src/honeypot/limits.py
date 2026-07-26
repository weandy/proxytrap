from __future__ import annotations

import asyncio
from collections import defaultdict


class ConnectionLimiter:
    """Process-wide connection budget for honeypot listeners."""

    def __init__(self, max_global: int, max_per_ip: int) -> None:
        self.max_global = max_global
        self.max_per_ip = max_per_ip
        self._global = 0
        self._per_ip: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def acquire(self, ip: str) -> bool:
        async with self._lock:
            if self._global >= self.max_global:
                return False
            if self._per_ip[ip] >= self.max_per_ip:
                return False
            self._global += 1
            self._per_ip[ip] += 1
            return True

    async def release(self, ip: str) -> None:
        async with self._lock:
            self._global = max(0, self._global - 1)
            if ip in self._per_ip:
                self._per_ip[ip] = max(0, self._per_ip[ip] - 1)
                if self._per_ip[ip] == 0:
                    del self._per_ip[ip]

    def snapshot(self) -> dict[str, int]:
        return {
            "global": self._global,
            "unique_ips": len(self._per_ip),
            "max_global": self.max_global,
            "max_per_ip": self.max_per_ip,
        }
