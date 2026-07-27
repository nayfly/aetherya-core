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


# ---------------------------------------------------------------------------
# Eviction must never reset a throttled window
# ---------------------------------------------------------------------------


def test_flooding_cannot_reset_a_throttled_actor_that_backed_off() -> None:
    """
    Regression, and the reason eviction is not plain LRU.

    A throttled client backs off — that is correct client behaviour — which
    makes it the least recently used entry and therefore the first thing plain
    LRU drops. Dropping it resets its limit, so an attacker could lift a
    victim's throttle just by flooding distinct actor ids. The victim here never
    calls again after being blocked.
    """
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=2, max_actors=50, sweep_every=10_000)
    )
    assert limiter.check("victim") is True
    assert limiter.check("victim") is True
    assert limiter.check("victim") is False

    for i in range(2_000):
        limiter.check(f"flood-{i}")

    assert limiter.check("victim") is False, "throttle was reset by cardinality flooding"
    assert limiter.tracked_actors() <= 50


def test_new_actors_are_refused_when_every_window_is_throttled() -> None:
    """
    Fail-closed under cardinality pressure: denying an unknown actor is strictly
    safer than forgetting a throttled one.
    """
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=1, max_actors=3, sweep_every=10_000)
    )
    for actor in ("a", "b", "c"):
        assert limiter.check(actor) is True
        assert limiter.check(actor) is False

    assert limiter.check("newcomer") is False
    assert limiter.capacity_refusals == 1
    assert limiter.tracked_actors() == 3


def test_non_throttled_windows_are_still_evicted_to_hold_the_cap() -> None:
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=10, max_actors=25, sweep_every=10_000)
    )
    for i in range(5_000):
        limiter.check(f"actor-{i}")

    assert limiter.tracked_actors() <= 25
    assert limiter.capacity_refusals == 0


def test_a_known_actor_is_never_refused_for_capacity() -> None:
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=1, max_actors=2, sweep_every=10_000)
    )
    limiter.check("a")
    limiter.check("a")
    limiter.check("b")
    limiter.check("b")
    # Both windows throttled and at capacity; a known actor still gets an answer.
    assert limiter.check("a") is False
    assert limiter.capacity_refusals == 0


def test_expired_windows_free_capacity_again() -> None:
    limiter = ActorRateLimiter(
        RateLimitConfig(requests_per_window=1, window_seconds=0.1, max_actors=2, sweep_every=10_000)
    )
    for actor in ("a", "b"):
        limiter.check(actor)
        limiter.check(actor)
    assert limiter.check("newcomer") is False

    time.sleep(0.15)
    assert limiter.check("newcomer") is True


def test_capacity_refusals_starts_at_zero() -> None:
    assert ActorRateLimiter().capacity_refusals == 0


def test_capacity_is_reclaimed_when_max_actors_is_lowered_at_runtime() -> None:
    """Eviction keeps freeing slots until the (possibly reduced) cap is met."""
    config = RateLimitConfig(requests_per_window=10, max_actors=20, sweep_every=10_000)
    limiter = ActorRateLimiter(config)
    for i in range(20):
        limiter.check(f"actor-{i}")
    assert limiter.tracked_actors() == 20

    config.max_actors = 5
    assert limiter.check("newcomer") is True
    assert limiter.tracked_actors() <= 5
