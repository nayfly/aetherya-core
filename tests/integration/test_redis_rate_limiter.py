"""
Integration tests for `RedisActorRateLimiter` against a real Redis.

The unit suite uses an in-memory double, which cannot demonstrate the
properties that actually matter here: real MULTI/EXEC semantics, serialization
between concurrent clients, TTL behaviour, or that separate limiter instances
(standing in for separate workers) genuinely share state.

Set `AETHERYA_TEST_REDIS_URL` to run these; they skip otherwise.

    docker run --rm -p 6379:6379 redis:7-alpine
    AETHERYA_TEST_REDIS_URL=redis://127.0.0.1:6379/15 pytest tests/integration -m integration
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from typing import Any

import pytest

from aetherya.rate_limiter import (
    RateLimitConfig,
    RedisActorRateLimiter,
    _redis_client_from_url,
    build_rate_limiter,
)

pytestmark = pytest.mark.integration

_URL_ENV = "AETHERYA_TEST_REDIS_URL"


@pytest.fixture(scope="module")
def redis_url() -> str:
    url = os.getenv(_URL_ENV, "").strip()
    if not url:
        pytest.skip(f"{_URL_ENV} not set — real-Redis integration tests skipped")
    return url


@pytest.fixture
def client(redis_url: str) -> Any:
    try:
        conn = _redis_client_from_url(redis_url)
        conn.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Redis unreachable at {redis_url}: {type(exc).__name__}: {exc}")
    return conn


@pytest.fixture
def prefix() -> str:
    """Unique per test so parallel runs and reruns cannot collide."""
    return f"aetherya:test:{uuid.uuid4().hex}"


def _limiter(client: Any, prefix: str, **kwargs: Any) -> RedisActorRateLimiter:
    return RedisActorRateLimiter(client, RateLimitConfig(**kwargs), prefix=prefix)


# ---------------------------------------------------------------------------
# Concurrency: the property the in-memory double cannot prove
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("threads", [50, 100])
def test_concurrent_clients_grant_exactly_n_permits(client: Any, prefix: str, threads: int) -> None:
    """
    N threads hammering one actor must yield exactly `requests_per_window`
    allows. Any interleaving where two workers read the same count before
    either writes would over-grant; this is what MULTI/EXEC has to prevent.
    """
    limit = 10
    limiter = _limiter(client, prefix, requests_per_window=limit, window_seconds=60.0)

    results: list[bool] = []
    results_lock = threading.Lock()
    start = threading.Barrier(threads)

    def worker() -> None:
        start.wait(timeout=10)
        allowed = limiter.check("contended-actor")
        with results_lock:
            results.append(allowed)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=30)

    assert len(results) == threads
    assert sum(results) == limit, f"expected exactly {limit} permits, got {sum(results)}"


def test_separate_limiter_instances_share_one_window(client: Any, prefix: str) -> None:
    """Two instances stand in for two workers: the limit must be global, not per-process."""
    worker_a = _limiter(client, prefix, requests_per_window=3, window_seconds=60.0)
    worker_b = _limiter(client, prefix, requests_per_window=3, window_seconds=60.0)

    assert worker_a.check("shared") is True
    assert worker_b.check("shared") is True
    assert worker_a.check("shared") is True
    # Budget exhausted across both instances.
    assert worker_b.check("shared") is False
    assert worker_a.check("shared") is False


def test_concurrent_distinct_actors_are_isolated(client: Any, prefix: str) -> None:
    limiter = _limiter(client, prefix, requests_per_window=2, window_seconds=60.0)
    outcomes: dict[str, list[bool]] = {}
    lock = threading.Lock()

    def worker(actor: str) -> None:
        got = [limiter.check(actor) for _ in range(4)]
        with lock:
            outcomes[actor] = got

    workers = [threading.Thread(target=worker, args=(f"actor-{i}",)) for i in range(20)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=30)

    assert len(outcomes) == 20
    for actor, got in outcomes.items():
        assert sum(got) == 2, f"{actor} got {sum(got)} permits, expected 2"


# ---------------------------------------------------------------------------
# Window behaviour against a real clock and a real server
# ---------------------------------------------------------------------------


def test_window_expires_and_the_actor_recovers(client: Any, prefix: str) -> None:
    limiter = _limiter(client, prefix, requests_per_window=2, window_seconds=1.0)

    assert limiter.check("recovering") is True
    assert limiter.check("recovering") is True
    assert limiter.check("recovering") is False

    time.sleep(1.2)
    assert limiter.check("recovering") is True


def test_throttled_retries_do_not_extend_the_window(client: Any, prefix: str) -> None:
    """
    A client hammering while blocked must not push its own window forward, or it
    would stay blocked past the intended duration.
    """
    limiter = _limiter(client, prefix, requests_per_window=1, window_seconds=1.0)
    assert limiter.check("hammering") is True

    deadline = time.time() + 0.9
    while time.time() < deadline:
        assert limiter.check("hammering") is False
        time.sleep(0.05)

    time.sleep(0.3)
    assert limiter.check("hammering") is True


def test_key_carries_a_bounded_ttl(client: Any, prefix: str) -> None:
    """Idle actors must expire on their own — no sweep runs against Redis."""
    limiter = _limiter(client, prefix, requests_per_window=5, window_seconds=30.0)
    limiter.check("ttl-actor")

    ttl = client.ttl(f"{prefix}:ttl-actor")
    assert 0 < ttl <= 31


def test_reset_clears_shared_state(client: Any, prefix: str) -> None:
    worker_a = _limiter(client, prefix, requests_per_window=1, window_seconds=60.0)
    worker_b = _limiter(client, prefix, requests_per_window=1, window_seconds=60.0)

    assert worker_a.check("resettable") is True
    assert worker_b.check("resettable") is False

    worker_a.reset("resettable")
    assert worker_b.check("resettable") is True


def test_tracked_actors_reflects_real_keys(client: Any, prefix: str) -> None:
    limiter = _limiter(client, prefix, requests_per_window=5, window_seconds=60.0)
    for i in range(5):
        limiter.check(f"counted-{i}")
    assert limiter.tracked_actors() == 5


# ---------------------------------------------------------------------------
# Failure behaviour
# ---------------------------------------------------------------------------


def test_unreachable_redis_refuses_requests(prefix: str) -> None:
    """Fail-closed against a real connection failure, not a mocked exception."""
    dead = _redis_client_from_url("redis://127.0.0.1:1/0")
    limiter = RedisActorRateLimiter(dead, RateLimitConfig(requests_per_window=100), prefix=prefix)
    assert limiter.check("anyone") is False


def test_connection_recovers_after_a_transient_failure(
    client: Any, redis_url: str, prefix: str
) -> None:
    """A closed connection must not permanently wedge the limiter."""
    limiter = _limiter(client, prefix, requests_per_window=5, window_seconds=60.0)
    assert limiter.check("recovering-conn") is True

    client.connection_pool.disconnect()
    # redis-py reconnects transparently on the next command.
    assert limiter.check("recovering-conn") is True


def test_factory_builds_a_working_limiter(
    monkeypatch: pytest.MonkeyPatch, redis_url: str, prefix: str
) -> None:
    monkeypatch.setenv("AETHERYA_RATE_LIMIT_REDIS_URL", redis_url)
    limiter = build_rate_limiter(
        "redis",
        RateLimitConfig(requests_per_window=2, window_seconds=60.0),
        redis_prefix=prefix,
    )
    assert isinstance(limiter, RedisActorRateLimiter)
    assert limiter.check("factory-actor") is True
    assert limiter.check("factory-actor") is True
    assert limiter.check("factory-actor") is False


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


def test_pipeline_fails_closed_when_the_limit_is_reached(client: Any, prefix: str) -> None:
    from aetherya.config import load_policy_config
    from aetherya.constitution import Constitution, Principle
    from aetherya.pipeline import run_pipeline

    cfg = load_policy_config("config/policy.yaml")
    core = Constitution(
        [Principle("NonHarm", "no harm", priority=1, keywords=[], risk=0)], use_semantic=False
    )
    limiter = _limiter(client, prefix, requests_per_window=2, window_seconds=60.0)

    decisions = [
        run_pipeline("help user", core, "pipeline-actor", cfg, rate_limiter=limiter)
        for _ in range(3)
    ]

    assert decisions[0].allowed is True
    assert decisions[1].allowed is True
    assert decisions[2].allowed is False
    assert "rate_limit" in decisions[2].reason
