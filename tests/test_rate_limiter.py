from __future__ import annotations

import time

from aetherya.rate_limiter import ActorRateLimiter, RateLimitConfig


def test_rate_limiter_allows_within_limit() -> None:
    limiter = ActorRateLimiter(RateLimitConfig(requests_per_window=5, window_seconds=60.0))
    for _ in range(5):
        assert limiter.check("alice") is True


def test_rate_limiter_blocks_over_limit() -> None:
    limiter = ActorRateLimiter(RateLimitConfig(requests_per_window=3, window_seconds=60.0))
    assert limiter.check("bob") is True
    assert limiter.check("bob") is True
    assert limiter.check("bob") is True
    assert limiter.check("bob") is False


def test_rate_limiter_independent_per_actor() -> None:
    limiter = ActorRateLimiter(RateLimitConfig(requests_per_window=2, window_seconds=60.0))
    assert limiter.check("alice") is True
    assert limiter.check("alice") is True
    assert limiter.check("alice") is False
    # bob is independent
    assert limiter.check("bob") is True
    assert limiter.check("bob") is True
    assert limiter.check("bob") is False


def test_rate_limiter_reset_clears_window() -> None:
    limiter = ActorRateLimiter(RateLimitConfig(requests_per_window=1, window_seconds=60.0))
    assert limiter.check("carol") is True
    assert limiter.check("carol") is False
    limiter.reset("carol")
    assert limiter.check("carol") is True


def test_rate_limiter_reset_unknown_actor_is_noop() -> None:
    limiter = ActorRateLimiter()
    limiter.reset("nonexistent")  # should not raise


def test_rate_limiter_default_config() -> None:
    limiter = ActorRateLimiter()
    assert limiter.check("dave") is True


def test_rate_limiter_sliding_window_expires() -> None:
    limiter = ActorRateLimiter(RateLimitConfig(requests_per_window=1, window_seconds=0.1))
    assert limiter.check("eve") is True
    assert limiter.check("eve") is False
    time.sleep(0.15)
    assert limiter.check("eve") is True


def test_rate_limiter_pipeline_integration(tmp_path: Path) -> None:  # noqa: F821
    from aetherya.config import load_policy_config
    from aetherya.constitution import Constitution, Principle
    from aetherya.pipeline import run_pipeline

    cfg = load_policy_config("config/policy.yaml")
    constitution = Constitution([Principle("NonHarm", "no harm", priority=1, keywords=[], risk=0)])
    limiter = ActorRateLimiter(RateLimitConfig(requests_per_window=2, window_seconds=60.0))

    d1 = run_pipeline(
        "help user", constitution=constitution, actor="frank", cfg=cfg, rate_limiter=limiter
    )
    d2 = run_pipeline(
        "help user", constitution=constitution, actor="frank", cfg=cfg, rate_limiter=limiter
    )
    d3 = run_pipeline(
        "help user", constitution=constitution, actor="frank", cfg=cfg, rate_limiter=limiter
    )

    assert d1.allowed is True
    assert d2.allowed is True
    assert d3.allowed is False
    assert "rate_limit" in d3.reason


def test_rate_limiter_none_means_no_limit() -> None:
    from aetherya.config import load_policy_config
    from aetherya.constitution import Constitution, Principle
    from aetherya.pipeline import run_pipeline

    cfg = load_policy_config("config/policy.yaml")
    constitution = Constitution([Principle("NonHarm", "no harm", priority=1, keywords=[], risk=0)])

    for _ in range(10):
        d = run_pipeline(
            "help user", constitution=constitution, actor="grace", cfg=cfg, rate_limiter=None
        )
        assert d.allowed is True
