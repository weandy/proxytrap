from __future__ import annotations

import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class LoginGuard:
    max_failures: int = 5
    ban_minutes: int = 15
    failures: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    banned_until: dict[str, float] = field(default_factory=dict)

    def is_banned(self, ip: str) -> bool:
        until = self.banned_until.get(ip)
        if until is None:
            return False
        if time.time() >= until:
            del self.banned_until[ip]
            self.failures[ip] = 0
            return False
        return True

    def register_failure(self, ip: str) -> None:
        self.failures[ip] += 1
        if self.failures[ip] >= self.max_failures:
            self.banned_until[ip] = time.time() + self.ban_minutes * 60

    def register_success(self, ip: str) -> None:
        self.failures.pop(ip, None)
        self.banned_until.pop(ip, None)


def constant_time_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
