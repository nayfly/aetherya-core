from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    requests_per_window: int = 60
    window_seconds: float = 60.0
    # Upper bound on tracked actors. Reached only under actor-id flooding;
    # eviction is least-recently-used so active actors are never displaced.
    max_actors: int = 10_000
    # Full sweep of fully-expired windows every N checks (amortized O(n)).
    sweep_every: int = 1_000


class ActorRateLimiter:
    """
    In-memory, per-actor sliding-window rate limiter.

    SINGLE-PROCESS SAFEGUARD: This limiter maintains state in-process only.
    In multi-process deployments (uvicorn --workers N, gunicorn), each worker
    has its own independent window. The effective rate limit across all workers
    is N × requests_per_window, not requests_per_window.

    For distributed rate limiting, implement a Redis-backed variant using the
    same Redis infrastructure already available for confirmation replay.

    BOUNDED STATE: windows are held in an LRU map capped at `max_actors`, and
    fully-expired windows are swept every `sweep_every` checks. Without this an
    attacker rotating the actor field grows the map without limit. LRU order is
    what makes eviction safe: an actor being actively rate-limited is by
    definition recently used, so flooding cannot evict — and thereby reset — the
    window of the actor it is trying to displace.
    """

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self._config = config or RateLimitConfig()
        self._lock = threading.Lock()
        self._windows: OrderedDict[str, deque[float]] = OrderedDict()
        self._checks_since_sweep = 0

    def _sweep(self, cutoff: float) -> None:
        """Drop windows whose most recent timestamp already fell out of the window."""
        stale = [
            actor for actor, window in self._windows.items() if not window or window[-1] <= cutoff
        ]
        for actor in stale:
            del self._windows[actor]

    def _evict_to_capacity(self) -> None:
        max_actors = self._config.max_actors
        if max_actors <= 0:
            return
        while len(self._windows) > max_actors:
            # popitem(last=False) removes the least-recently-used actor.
            self._windows.popitem(last=False)

    def check(self, actor: str) -> bool:
        """Return True if the request is allowed, False if throttled."""
        now = time.monotonic()
        cutoff = now - self._config.window_seconds
        with self._lock:
            self._checks_since_sweep += 1
            if self._checks_since_sweep >= self._config.sweep_every:
                self._checks_since_sweep = 0
                self._sweep(cutoff)

            window = self._windows.get(actor)
            if window is None:
                window = deque()
                self._windows[actor] = window
            else:
                # Mark as most-recently-used so LRU eviction never targets it.
                self._windows.move_to_end(actor)

            # Evict timestamps outside the sliding window
            while window and window[0] <= cutoff:
                window.popleft()

            if len(window) >= self._config.requests_per_window:
                self._evict_to_capacity()
                return False

            window.append(now)
            self._evict_to_capacity()
            return True

    def reset(self, actor: str) -> None:
        """Clear the sliding window for an actor (for tests and admin use)."""
        with self._lock:
            self._windows.pop(actor, None)

    def tracked_actors(self) -> int:
        """Number of actor windows currently retained (observability and tests)."""
        with self._lock:
            return len(self._windows)
