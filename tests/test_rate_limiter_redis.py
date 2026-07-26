from __future__ import annotations

import time
from typing import Any

import pytest

from aetherya.config import RateLimitBackendConfig, load_policy_config
from aetherya.rate_limiter import (
    ActorRateLimiter,
    RateLimitConfig,
    RedisActorRateLimiter,
    build_rate_limiter,
)


class FakeRedis:
    """
    Minimal in-memory stand-in implementing the sorted-set surface the limiter
    uses. Pipelines execute eagerly in order, which matches the semantics the
    limiter relies on (zcard observed before its own zadd).
    """

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.expiries: dict[str, int] = {}
        self.fail = False
        self.commands: list[str] = []

    # -- sorted set primitives ------------------------------------------------

    def zremrangebyscore(self, key: str, low: float, high: float) -> int:
        members = self.zsets.setdefault(key, {})
        doomed = [m for m, score in members.items() if low <= score <= high]
        for m in doomed:
            del members[m]
        return len(doomed)

    def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        self.zsets.setdefault(key, {}).update(mapping)
        return len(mapping)

    def zrem(self, key: str, member: str) -> int:
        return 1 if self.zsets.get(key, {}).pop(member, None) is not None else 0

    def expire(self, key: str, ttl: int) -> bool:
        self.expiries[key] = ttl
        return True

    def delete(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.expiries.pop(key, None)
        return 1 if self.zsets.pop(key, None) is not None else 0

    def scan_iter(self, match: str = "*") -> Any:
        prefix = match.rstrip("*")
        return iter([k for k in self.zsets if k.startswith(prefix)])

    # -- pipeline -------------------------------------------------------------

    def pipeline(self) -> FakePipeline:
        if self.fail:
            raise ConnectionError("redis unavailable")
        return FakePipeline(self)


class FakePipeline:
    def __init__(self, client: FakeRedis) -> None:
        self._client = client
        self._queued: list[tuple[str, tuple[Any, ...]]] = []

    def zremrangebyscore(self, *args: Any) -> FakePipeline:
        self._queued.append(("zremrangebyscore", args))
        return self

    def zcard(self, *args: Any) -> FakePipeline:
        self._queued.append(("zcard", args))
        return self

    def zadd(self, *args: Any) -> FakePipeline:
        self._queued.append(("zadd", args))
        return self

    def expire(self, *args: Any) -> FakePipeline:
        self._queued.append(("expire", args))
        return self

    def execute(self) -> list[Any]:
        if self._client.fail:
            raise ConnectionError("redis unavailable")
        results = []
        for name, args in self._queued:
            self._client.commands.append(name)
            results.append(getattr(self._client, name)(*args))
        self._queued.clear()
        return results


def _limiter(client: FakeRedis, **kwargs: Any) -> RedisActorRateLimiter:
    return RedisActorRateLimiter(client, RateLimitConfig(**kwargs))


# ---------------------------------------------------------------------------
# Core limiting behaviour
# ---------------------------------------------------------------------------


def test_allows_within_limit_and_blocks_beyond() -> None:
    limiter = _limiter(FakeRedis(), requests_per_window=3, window_seconds=60.0)
    assert [limiter.check("alice") for _ in range(4)] == [True, True, True, False]


def test_actors_are_independent() -> None:
    limiter = _limiter(FakeRedis(), requests_per_window=1, window_seconds=60.0)
    assert limiter.check("alice") is True
    assert limiter.check("alice") is False
    assert limiter.check("bob") is True


def test_window_slides() -> None:
    limiter = _limiter(FakeRedis(), requests_per_window=1, window_seconds=0.1)
    assert limiter.check("eve") is True
    assert limiter.check("eve") is False
    time.sleep(0.15)
    assert limiter.check("eve") is True


def test_throttled_request_does_not_extend_its_own_window() -> None:
    """
    A refused request must not leave its timestamp behind: otherwise a caller
    hammering the endpoint would keep pushing its own window forward and stay
    blocked past the intended duration.
    """
    client = FakeRedis()
    limiter = _limiter(client, requests_per_window=2, window_seconds=60.0)
    limiter.check("mallory")
    limiter.check("mallory")
    for _ in range(10):
        assert limiter.check("mallory") is False

    assert client.zcard("aetherya:ratelimit:mallory") == 2


def test_requests_in_the_same_clock_tick_both_count() -> None:
    """Members must be unique — a timestamp-only member would collapse them."""
    client = FakeRedis()
    limiter = _limiter(client, requests_per_window=5, window_seconds=60.0)
    for _ in range(3):
        limiter.check("fast")
    assert client.zcard("aetherya:ratelimit:fast") == 3


def test_keys_carry_a_ttl_so_idle_actors_expire() -> None:
    client = FakeRedis()
    _limiter(client, requests_per_window=5, window_seconds=30.0).check("alice")
    assert client.expiries["aetherya:ratelimit:alice"] == 31


def test_reset_clears_the_window() -> None:
    limiter = _limiter(FakeRedis(), requests_per_window=1, window_seconds=60.0)
    assert limiter.check("carol") is True
    assert limiter.check("carol") is False
    limiter.reset("carol")
    assert limiter.check("carol") is True


def test_custom_prefix_is_honoured() -> None:
    client = FakeRedis()
    RedisActorRateLimiter(client, prefix="custom:rl").check("alice")
    assert "custom:rl:alice" in client.zsets


def test_blank_prefix_falls_back_to_the_default() -> None:
    client = FakeRedis()
    RedisActorRateLimiter(client, prefix="   ").check("alice")
    assert "aetherya:ratelimit:alice" in client.zsets


def test_tracked_actors_counts_windows() -> None:
    client = FakeRedis()
    limiter = RedisActorRateLimiter(client)
    limiter.check("alice")
    limiter.check("bob")
    assert limiter.tracked_actors() == 2


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


def test_unreachable_redis_refuses_the_request() -> None:
    """A limiter that fails open is not a limiter."""
    client = FakeRedis()
    limiter = _limiter(client, requests_per_window=100, window_seconds=60.0)
    assert limiter.check("alice") is True

    client.fail = True
    assert limiter.check("alice") is False


def test_reset_survives_an_unreachable_redis() -> None:
    client = FakeRedis()
    client.fail = True
    RedisActorRateLimiter(client).reset("alice")  # must not raise


def test_tracked_actors_survives_an_unreachable_redis() -> None:
    client = FakeRedis()
    client.fail = True

    def _boom(match: str = "*") -> Any:
        raise ConnectionError("down")

    client.scan_iter = _boom  # type: ignore[method-assign]
    assert RedisActorRateLimiter(client).tracked_actors() == 0


def test_zrem_failure_on_the_throttled_path_is_contained() -> None:
    client = FakeRedis()
    limiter = _limiter(client, requests_per_window=1, window_seconds=60.0)
    limiter.check("alice")

    def _boom(key: str, member: str) -> int:
        raise ConnectionError("down")

    client.zrem = _boom  # type: ignore[method-assign]
    assert limiter.check("alice") is False


def test_short_pipeline_result_is_treated_as_empty() -> None:
    client = FakeRedis()

    class _ShortPipeline(FakePipeline):
        def execute(self) -> list[Any]:
            super().execute()
            return []

    client.pipeline = lambda: _ShortPipeline(client)  # type: ignore[method-assign]
    assert RedisActorRateLimiter(client).check("alice") is True


# ---------------------------------------------------------------------------
# Backend factory and configuration
# ---------------------------------------------------------------------------


def test_factory_builds_the_memory_backend() -> None:
    assert isinstance(build_rate_limiter("memory"), ActorRateLimiter)


def test_factory_builds_the_redis_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.rate_limiter as module

    monkeypatch.setenv("AETHERYA_RATE_LIMIT_REDIS_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.setattr(module, "_redis_client_from_url", lambda _url: FakeRedis())

    limiter = build_rate_limiter("redis", RateLimitConfig(requests_per_window=1))
    assert isinstance(limiter, RedisActorRateLimiter)
    assert limiter.check("alice") is True
    assert limiter.check("alice") is False


def test_factory_requires_a_url_for_the_redis_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AETHERYA_RATE_LIMIT_REDIS_URL", raising=False)
    with pytest.raises(RuntimeError, match="URL env is missing"):
        build_rate_limiter("redis")


def test_factory_rejects_an_unknown_backend() -> None:
    with pytest.raises(ValueError, match="unsupported rate limiter backend"):
        build_rate_limiter("cassandra")


def test_factory_defaults_to_memory_for_blank_backend() -> None:
    assert isinstance(build_rate_limiter(""), ActorRateLimiter)


def test_redis_client_from_url_prefers_module_level_from_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.rate_limiter as module

    class _Module:
        @staticmethod
        def from_url(url: str, decode_responses: bool = False) -> str:
            return f"client:{url}:{decode_responses}"

    monkeypatch.setattr(module.importlib, "import_module", lambda _n: _Module())
    assert module._redis_client_from_url("redis://x") == "client:redis://x:True"


def test_redis_client_from_url_falls_back_to_the_class(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.rate_limiter as module

    class _Redis:
        @staticmethod
        def from_url(url: str, decode_responses: bool = False) -> str:
            return f"cls:{url}"

    class _Module:
        Redis = _Redis

    monkeypatch.setattr(module.importlib, "import_module", lambda _n: _Module())
    assert module._redis_client_from_url("redis://x") == "cls:redis://x"


def test_redis_client_from_url_rejects_a_module_without_a_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.rate_limiter as module

    class _Module:
        pass

    monkeypatch.setattr(module.importlib, "import_module", lambda _n: _Module())
    with pytest.raises(RuntimeError, match="does not expose Redis client"):
        module._redis_client_from_url("redis://x")


def test_redis_client_from_url_rejects_a_client_without_from_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.rate_limiter as module

    class _Redis:
        pass

    class _Module:
        Redis = _Redis

    monkeypatch.setattr(module.importlib, "import_module", lambda _n: _Module())
    with pytest.raises(RuntimeError, match="does not support from_url"):
        module._redis_client_from_url("redis://x")


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------


def test_policy_exposes_the_rate_limit_backend() -> None:
    cfg = load_policy_config("config/policy.yaml")
    assert cfg.rate_limit.backend == "memory"
    assert cfg.rate_limit.requests_per_window == 60


def test_default_rate_limit_config_matches_the_dataclass_defaults() -> None:
    assert RateLimitBackendConfig().backend == "memory"
    assert RateLimitBackendConfig().redis_url_env == "AETHERYA_RATE_LIMIT_REDIS_URL"


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"backend": "cassandra"}, "backend must be one of"),
        ({"requests_per_window": 0}, "requests_per_window must be >= 1"),
        ({"window_seconds": 0}, "window_seconds must be > 0"),
    ],
)
def test_policy_rejects_invalid_rate_limit_config(
    tmp_path: Any, overrides: dict[str, Any], expected_error: str
) -> None:
    from pathlib import Path

    import yaml

    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    data["rate_limit"].update(overrides)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match=expected_error):
        load_policy_config(path)
