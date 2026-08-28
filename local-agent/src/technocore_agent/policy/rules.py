from __future__ import annotations

import hashlib
import time


class PolicyError(ValueError):
    pass


def validate_route(url: str, path: str) -> None:
    if url != "https://" + "technocore.chat" or not path.startswith("/r/") or path.count("/") != 2:
        raise PolicyError("route is not an approved signed-room route")


class DuplicateGuard:
    def __init__(self, window_seconds: float = 3600) -> None:
        self.window_seconds, self._seen = window_seconds, {}

    def check(self, room: str, text: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        digest = hashlib.sha256(f"{room}\0{text}".encode()).hexdigest()
        if digest in self._seen and now - self._seen[digest] < self.window_seconds:
            raise PolicyError("duplicate content is blocked")
        self._seen[digest] = now


class WriteBudget:
    def __init__(self, limit: int) -> None:
        self.limit, self.used = limit, 0

    def consume_write(self) -> None:
        if self.used >= self.limit:
            raise PolicyError("signed-write budget exhausted")
        self.used += 1

    def observe_read(self) -> None:
        pass
