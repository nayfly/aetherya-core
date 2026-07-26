from __future__ import annotations

import importlib
import os
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class RateLimitConfig:
    requests_per_window: int = 60
    window_seconds: float = 60.0
    # Upper bound on tracked actors. Reached only under actor-id flooding;
    # eviction is least-recently-used so active actors are never displaced.
    max_actors: int = 10_000
    # Full sweep of fully-expired windows every N checks (amortized O(n)).
    sweep_every: int = 1_000


class RateLimiter(Protocol):
    """Shared surface of the in-process and Redis-backed limiters."""

    def check(self, actor: str) -> bool: ...

    def reset(self, actor: str) -> None: ...


class ActorRateLimiter:
    """
    In-memory, per-actor sliding-window rate limiter.

    SINGLE-PROCESS SAFEGUARD: This limiter maintains state in-process only.
    In multi-process deployments (uvicorn --workers N, gunicorn), each worker
    has its own independent window. The effective rate limit across all workers
    is N × requests_per_window, not requests_per_window.

    Use `RedisActorRateLimiter` (or `build_rate_limiter("redis", ...)`) whenever
    more than one worker or replica shares a limit.

    BOUNDED STATE: windows are held in an LRU map capped at `max_actors`, and
    fully-expired windows are swept every `sweep_every` checks. Without this an
    attacker rotating the actor field grows the map without limit.

    EVICTION IS NOT PURELY LRU, and the difference is a security property.
    Recency alone is not safe here: a throttled client backs off — that is the
    correct client behaviour — which makes it the *least* recently used entry
    and therefore the first thing plain LRU would drop. Dropping it resets its
    limit, so an attacker could lift a victim's throttle just by flooding
    distinct actor ids. Windows at or above the limit are consequently never
    evicted. When no evictable window remains, a *new* actor is refused instead
    (fail-closed): under extreme cardinality pressure the limiter denies unknown
    actors rather than forgetting throttled ones.
    """

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self._config = config or RateLimitConfig()
        self._lock = threading.Lock()
        self._windows: OrderedDict[str, deque[float]] = OrderedDict()
        self._checks_since_sweep = 0
        # Number of new actors refused because capacity could not be freed
        # without resetting a throttled window. A non-zero value means the
        # limiter is under cardinality pressure — worth alerting on.
        self.capacity_refusals = 0

    def _prune(self, window: deque[float], cutoff: float) -> None:
        while window and window[0] <= cutoff:
            window.popleft()

    def _sweep(self, cutoff: float) -> None:
        """Drop windows whose most recent timestamp already fell out of the window."""
        stale = [
            actor for actor, window in self._windows.items() if not window or window[-1] <= cutoff
        ]
        for actor in stale:
            del self._windows[actor]

    def _make_room_for_new_actor(self, cutoff: float) -> bool:
        """
        Free a slot for an actor we have not seen before.

        Returns False when every retained window is at or above the limit, i.e.
        the only way to make room would be to reset someone's throttle.
        """
        max_actors = self._config.max_actors
        if max_actors <= 0 or len(self._windows) < max_actors:
            return True

        limit = self._config.requests_per_window
        # Least-recently-used first, but skipping throttled windows.
        for candidate in list(self._windows):
            window = self._windows[candidate]
            self._prune(window, cutoff)
            if len(window) >= limit:
                continue  # throttled: evicting this would reset its limit
            del self._windows[candidate]
            if len(self._windows) < max_actors:
                return True

        return len(self._windows) < max_actors

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
                if not self._make_room_for_new_actor(cutoff):
                    self.capacity_refusals += 1
                    return False
                window = deque()
                self._windows[actor] = window
            else:
                # Known actor: mark most-recently-used.
                self._windows.move_to_end(actor)

            self._prune(window, cutoff)

            if len(window) >= self._config.requests_per_window:
                return False

            window.append(now)
            return True

    def reset(self, actor: str) -> None:
        """Clear the sliding window for an actor (for tests and admin use)."""
        with self._lock:
            self._windows.pop(actor, None)

    def tracked_actors(self) -> int:
        """Number of actor windows currently retained (observability and tests)."""
        with self._lock:
            return len(self._windows)


def _redis_client_from_url(url: str) -> Any:
    redis_module = importlib.import_module("redis")
    from_url = getattr(redis_module, "from_url", None)
    if callable(from_url):
        return from_url(url, decode_responses=True)

    redis_cls = getattr(redis_module, "Redis", None)
    if redis_cls is None:
        raise RuntimeError("redis module does not expose Redis client")
    from_url_method = getattr(redis_cls, "from_url", None)
    if not callable(from_url_method):
        raise RuntimeError("redis client does not support from_url")
    return from_url_method(url, decode_responses=True)


class RedisActorRateLimiter:
    """
    Sliding-window rate limiter shared across processes via Redis.

    WHY THIS EXISTS: `ActorRateLimiter` keeps its windows in process memory, so
    behind `uvicorn --workers N` the effective limit is N x requests_per_window.
    That is not a tuning inaccuracy — it means the configured limit is simply not
    the limit that applies, and it scales with replica count.

    IMPLEMENTATION: one sorted set per actor, scored by timestamp. Each check
    drops entries older than the window, counts what remains, and adds the
    current request. The four commands run in a single pipeline/transaction so
    concurrent workers cannot interleave a read against a stale count. Keys carry
    a TTL of one window, so idle actors expire without any sweep.

    FAIL-CLOSED: if Redis is unreachable the check returns False — the request is
    refused rather than silently falling back to unlimited. A rate limiter that
    fails open is not a rate limiter, and the pipeline already treats a refused
    check as `fail_closed:rate_limit`.
    """

    def __init__(
        self,
        client: Any,
        config: RateLimitConfig | None = None,
        *,
        prefix: str = "aetherya:ratelimit",
    ) -> None:
        self._client = client
        self._config = config or RateLimitConfig()
        self._prefix = prefix.strip() or "aetherya:ratelimit"

    def _key(self, actor: str) -> str:
        return f"{self._prefix}:{actor}"

    def check(self, actor: str) -> bool:
        """Return True if the request is allowed, False if throttled or Redis is down."""
        now = time.time()
        cutoff = now - self._config.window_seconds
        key = self._key(actor)
        # Unique member: two requests in the same clock tick must both count.
        member = f"{now:.9f}:{uuid.uuid4().hex}"
        ttl = max(1, int(self._config.window_seconds) + 1)

        try:
            pipe = self._client.pipeline()
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zcard(key)
            pipe.zadd(key, {member: now})
            pipe.expire(key, ttl)
            results = pipe.execute()
        except Exception:
            # Fail closed: no limiter state means no authorization to proceed.
            return False

        # zcard runs before our own zadd, so `count` excludes this request.
        count = int(results[1]) if len(results) > 1 else 0
        if count >= self._config.requests_per_window:
            # Over the limit: withdraw the entry we just added so a throttled
            # caller cannot extend its own window by retrying.
            try:
                self._client.zrem(key, member)
            except Exception:
                pass
            return False
        return True

    def reset(self, actor: str) -> None:
        """Clear the window for an actor (for tests and admin use)."""
        try:
            self._client.delete(self._key(actor))
        except Exception:
            pass

    def tracked_actors(self) -> int:
        """Number of actor windows currently held in Redis."""
        try:
            return int(len(list(self._client.scan_iter(match=f"{self._prefix}:*"))))
        except Exception:
            return 0


def build_rate_limiter(
    backend: str = "memory",
    config: RateLimitConfig | None = None,
    *,
    redis_url_env: str = "AETHERYA_RATE_LIMIT_REDIS_URL",
    redis_prefix: str = "aetherya:ratelimit",
) -> RateLimiter:
    """
    Construct the limiter named by `backend`.

    `memory` is correct only for single-process deployments. `redis` is required
    whenever more than one worker or replica shares a limit.
    """
    normalized = (backend or "memory").strip().lower()
    if normalized == "memory":
        return ActorRateLimiter(config)
    if normalized == "redis":
        url = os.getenv(redis_url_env, "").strip()
        if not url:
            raise RuntimeError(
                f"rate_limit backend=redis but the URL env is missing ({redis_url_env})"
            )
        return RedisActorRateLimiter(_redis_client_from_url(url), config, prefix=redis_prefix)
    raise ValueError(f"unsupported rate limiter backend: {backend}")
