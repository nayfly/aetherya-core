from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    requests_per_window: int = 60
    window_seconds: float = 60.0


class ActorRateLimiter:
    """
    In-memory, per-actor sliding-window rate limiter.

    SINGLE-PROCESS SAFEGUARD: This limiter maintains state in-process only.
    In multi-process deployments (uvicorn --workers N, gunicorn), each worker
    has its own independent window. The effective rate limit across all workers
    is N × requests_per_window, not requests_per_window.

    For distributed rate limiting, implement a Redis-backed variant using the
    same Redis infrastructure already available for confirmation replay.
    """

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self._config = config or RateLimitConfig()
        self._lock = threading.Lock()
        self._windows: dict[str, deque[float]] = {}

    def check(self, actor: str) -> bool:
        """Return True if the request is allowed, False if throttled."""
        now = time.monotonic()
        cutoff = now - self._config.window_seconds
        with self._lock:
            window = self._windows.setdefault(actor, deque())
            # Evict timestamps outside the sliding window
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= self._config.requests_per_window:
                return False
            window.append(now)
            return True

    def reset(self, actor: str) -> None:
        """Clear the sliding window for an actor (for tests and admin use)."""
        with self._lock:
            self._windows.pop(actor, None)
