from __future__ import annotations

import time

from aetherya.rate_limiter import ActorRateLimiter, RateLimitConfig


def test_actor_map_is_bounded_under_actor_id_flooding() -> None:
    """
    Regression: the window map grew one entry per distinct actor and never
    released them, so rotating the actor field was an unbounded memory leak.
    """
    limiter = ActorRateLimiter(RateLimitConfig(max_actors=500, sweep_every=100))
    for i in range(20_000):
        limiter.check(f"actor-{i}")
    assert limiter.tracked_actors() <= 500


def test_flooding_cannot_reset_an_active_actors_window() -> None:
    """
    LRU order is a security property, not just a memory one: if eviction hit
    active actors, an attacker could flood with junk ids to evict a throttled
    victim and reset its counter.
    """
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=2, max_actors=50, sweep_every=10_000)
    )
    assert limiter.check("victim") is True
    assert limiter.check("victim") is True
    assert limiter.check("victim") is False

    for i in range(2_000):
        limiter.check(f"flood-{i}")
        limiter.check("victim")  # victim stays recently-used

    assert limiter.check("victim") is False
    assert limiter.tracked_actors() <= 50


def test_sweep_releases_fully_expired_windows() -> None:
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=5, window_seconds=0.05, sweep_every=3)
    )
    for i in range(10):
        limiter.check(f"transient-{i}")
    assert limiter.tracked_actors() > 0

    time.sleep(0.1)
    # Any three checks trigger the amortized sweep.
    for _ in range(3):
        limiter.check("survivor")
    assert limiter.tracked_actors() == 1


def test_max_actors_zero_disables_the_cap() -> None:
    limiter = ActorRateLimiter(RateLimitConfig(max_actors=0, sweep_every=10_000))
    for i in range(300):
        limiter.check(f"actor-{i}")
    assert limiter.tracked_actors() == 300


def test_tracked_actors_reflects_reset() -> None:
    limiter = ActorRateLimiter()
    limiter.check("alice")
    limiter.check("bob")
    assert limiter.tracked_actors() == 2
    limiter.reset("alice")
    assert limiter.tracked_actors() == 1


def test_eviction_also_runs_on_the_throttled_path() -> None:
    """A throttled actor still returns early — capacity must be enforced there too."""
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=1, max_actors=5, sweep_every=10_000)
    )
    for i in range(50):
        limiter.check(f"actor-{i}")
        limiter.check(f"actor-{i}")  # second call is throttled
    assert limiter.tracked_actors() <= 5


def test_limits_are_still_enforced_after_eviction_pressure() -> None:
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=3, max_actors=10, sweep_every=10_000)
    )
    for i in range(100):
        limiter.check(f"noise-{i}")
    assert limiter.check("fresh") is True
    assert limiter.check("fresh") is True
    assert limiter.check("fresh") is True
    assert limiter.check("fresh") is False
