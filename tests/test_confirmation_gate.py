from __future__ import annotations

import time

import pytest

from aetherya.actions import ActionRequest
from aetherya.approval_proof import build_approval_proof
from aetherya.config import (
    ConfirmationConfig,
    ConfirmationEvidenceConfig,
    ConfirmationRequireConfig,
    ConfirmationSignedProofConfig,
)
from aetherya.confirmation_gate import ConfirmationGate, _InMemoryReplayStore, _RedisReplayStore
from aetherya.risk import RiskAggregate, RiskDecision, RiskSignal


def make_confirmation_gate(
    enabled: bool = True,
    *,
    decisions: list[str] | None = None,
    tools: list[str] | None = None,
    operations: list[str] | None = None,
    min_risk_score: int = 0,
    on_confirmed: str = "allow",
    signed_proof_enabled: bool = False,
    signed_proof_key_env: str = "AETHERYA_CONFIRMATION_HMAC_KEY",
    signed_proof_active_kid: str = "k1",
    signed_proof_replay_mode: str = "single_use",
    signed_proof_replay_store: str = "memory",
    signed_proof_replay_redis_url_env: str = "AETHERYA_CONFIRMATION_REPLAY_REDIS_URL",
    signed_proof_replay_redis_prefix: str = "aetherya:appr",
    replay_store=None,  # noqa: ANN001
) -> ConfirmationGate:
    require_decisions = decisions if decisions is not None else ["require_confirm"]
    require_tools = tools if tools is not None else []
    require_operations = operations if operations is not None else ["delete", "write"]
    cfg = ConfirmationConfig(
        enabled=enabled,
        on_confirmed=on_confirmed,
        require_for=ConfirmationRequireConfig(
            decisions=require_decisions,
            tools=require_tools,
            operations=require_operations,
            min_risk_score=min_risk_score,
        ),
        evidence=ConfirmationEvidenceConfig(
            token_param="confirm_token",
            context_param="confirm_context",
            token_pattern=r"^ack:[a-z0-9_-]{8,}$",
            min_context_length=12,
            signed_proof=ConfirmationSignedProofConfig(
                enabled=signed_proof_enabled,
                proof_param="confirm_proof",
                key_env=signed_proof_key_env,
                keyring_env="AETHERYA_CONFIRMATION_HMAC_KEYRING",
                active_kid=signed_proof_active_kid,
                max_valid_for_sec=300,
                clock_skew_sec=2,
                replay_mode=signed_proof_replay_mode,
                replay_store=signed_proof_replay_store,
                replay_redis_url_env=signed_proof_replay_redis_url_env,
                replay_redis_prefix=signed_proof_replay_redis_prefix,
            ),
        ),
    )
    return ConfirmationGate(cfg, replay_store=replay_store)


def make_aggregate(decision: RiskDecision, total: int = 60) -> RiskAggregate:
    return RiskAggregate(
        total_score=total,
        decision=decision,
        reasons=["x"],
        breakdown=[RiskSignal(source="constitution", score=total, reason="x")],
        top_signal=RiskSignal(source="constitution", score=total, reason="x"),
    )


def test_confirmation_gate_disabled_returns_none() -> None:
    gate = make_confirmation_gate(enabled=False)
    action = ActionRequest(raw_input="run", intent="operate", parameters={})
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM))
    assert out is None


def test_confirmation_gate_requires_evidence_for_require_confirm() -> None:
    gate = make_confirmation_gate()
    action = ActionRequest(raw_input="run", intent="operate", parameters={})
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM))
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_missing" in out["tags"]


def test_confirmation_gate_rejects_invalid_token() -> None:
    gate = make_confirmation_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        parameters={"confirm_token": "bad", "confirm_context": "enough_context_here"},
    )
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM))
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_invalid_token" in out["tags"]


def test_confirmation_gate_rejects_short_context() -> None:
    gate = make_confirmation_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        parameters={
            "confirm_token": "ack:abc12345",
            "confirm_context": "too short",
        },
    )
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM))
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_context_too_short" in out["tags"]


def test_confirmation_gate_accepts_valid_evidence_and_sets_override() -> None:
    gate = make_confirmation_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        parameters={
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM))
    assert out is not None
    assert out["confirmed"] is True
    assert out["override_decision"] == "allow"


def test_confirmation_gate_accepts_valid_evidence_without_override() -> None:
    gate = make_confirmation_gate(decisions=[], operations=["write"])
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        parameters={
            "operation": "write",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.LOG_ONLY, total=20))
    assert out is not None
    assert out["confirmed"] is True
    assert "override_decision" not in out


def test_confirmation_gate_requires_by_tool_when_configured() -> None:
    gate = make_confirmation_gate(decisions=[], tools=["filesystem"], operations=[])
    action = ActionRequest(raw_input="run", intent="operate", tool="filesystem", parameters={})
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.ALLOW, total=0))
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_missing" in out["tags"]


def test_confirmation_gate_requires_by_min_risk_score_threshold() -> None:
    gate = make_confirmation_gate(decisions=[], operations=[], min_risk_score=40)
    action = ActionRequest(raw_input="run", intent="operate", parameters={})
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.ALLOW, total=40))
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_missing" in out["tags"]


def test_confirmation_gate_not_required_for_safe_allow_path() -> None:
    gate = make_confirmation_gate()
    action = ActionRequest(raw_input="help", intent="ask", parameters={})
    out = gate.evaluate(action=action, aggregate=make_aggregate(RiskDecision.ALLOW, total=0))
    assert out is None


def test_confirmation_gate_requires_signed_proof_when_enabled() -> None:
    gate = make_confirmation_gate(signed_proof_enabled=True)
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        parameters={
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    out = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert out is not None
    assert out["confirmed"] is False
    assert out["proof_required"] is True
    assert out["proof_valid"] is False
    assert "confirmation_proof_missing" in out["tags"]


def test_confirmation_gate_rejects_missing_proof_key_env(
    monkeypatch,  # noqa: ANN001
) -> None:
    gate = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_MISSING_KEY",
    )
    monkeypatch.delenv("AETHERYA_TEST_MISSING_KEY", raising=False)
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        parameters={
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
            "confirm_proof": "ap1.1.n.sig",
        },
    )
    out = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_proof_key_missing" in out["tags"]


def test_confirmation_gate_accepts_valid_signed_proof(
    monkeypatch,  # noqa: ANN001
) -> None:
    gate = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_SIGN_KEY",
    )
    monkeypatch.setenv("AETHERYA_TEST_SIGN_KEY", "secret-signing-key")

    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        target="/tmp",
        parameters={
            "operation": "write",
            "path": "/tmp/a.txt",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="secret-signing-key",
        kid="k1",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=int(time.time()),
        exclude_params=excluded,
    )
    action.parameters["confirm_proof"] = proof

    out = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert out is not None
    assert out["confirmed"] is True
    assert out["proof_required"] is True
    assert out["proof_valid"] is True
    assert out["proof_kid"] == "k1"
    assert out["proof_scope_hash"].startswith("sha256:")
    assert out["override_decision"] == "allow"
    assert "confirmation_proof_validated" in out["tags"]


def test_confirmation_gate_rejects_signed_proof_bound_to_other_actor(
    monkeypatch,  # noqa: ANN001
) -> None:
    gate = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_ACTOR_KEY",
    )
    monkeypatch.setenv("AETHERYA_TEST_ACTOR_KEY", "actor-bound-key")

    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        target="/tmp",
        parameters={
            "operation": "write",
            "path": "/tmp/a.txt",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="actor-bound-key",
        kid="k1",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=int(time.time()),
        exclude_params=excluded,
    )
    action.parameters["confirm_proof"] = proof

    out = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="alice",
    )
    assert out is not None
    assert out["confirmed"] is False
    assert "confirmation_proof_invalid" in out["tags"]
    assert "confirmation_proof_scope_mismatch" in out["tags"]


def test_confirmation_gate_rejects_signed_proof_replay_single_use(
    monkeypatch,  # noqa: ANN001
) -> None:
    gate = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_REPLAY_KEY",
        signed_proof_replay_mode="single_use",
    )
    monkeypatch.setenv("AETHERYA_TEST_REPLAY_KEY", "replay-key")
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        target="/tmp",
        parameters={
            "operation": "write",
            "path": "/tmp/a.txt",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="replay-key",
        kid="k1",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=int(time.time()),
        nonce="replay123",
        exclude_params=excluded,
    )
    action.parameters["confirm_proof"] = proof

    out_first = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert out_first is not None
    assert out_first["confirmed"] is True

    out_second = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert out_second is not None
    assert out_second["confirmed"] is False
    assert "confirmation_proof_replay_rejected" in out_second["tags"]
    assert "confirmation_proof_replay_detected" in out_second["tags"]


def test_confirmation_gate_allows_idempotent_reuse_for_same_scope(
    monkeypatch,  # noqa: ANN001
) -> None:
    gate = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_IDEMPOTENT_KEY",
        signed_proof_replay_mode="idempotent",
    )
    monkeypatch.setenv("AETHERYA_TEST_IDEMPOTENT_KEY", "idempotent-key")
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        target="/tmp",
        parameters={
            "operation": "write",
            "path": "/tmp/a.txt",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="idempotent-key",
        kid="k1",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=int(time.time()),
        nonce="same-nonce",
        exclude_params=excluded,
    )
    action.parameters["confirm_proof"] = proof

    out_first = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    out_second = gate.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert out_first is not None and out_first["confirmed"] is True
    assert out_second is not None and out_second["confirmed"] is True


def test_replay_store_cleanup_and_expired_refresh(monkeypatch) -> None:  # noqa: ANN001
    store = _InMemoryReplayStore()
    store._entries[("k1", "stale")] = ("sha256:aaa", 5)  # noqa: SLF001
    monkeypatch.setattr("aetherya.confirmation_gate.time.time", lambda: 10.0)
    assert (
        store.check_and_mark(
            kid="k1",
            nonce="fresh",
            scope_hash="sha256:bbb",
            expires_at=20,
            replay_mode="single_use",
        )
        == "ok"
    )
    assert ("k1", "stale") not in store._entries  # noqa: SLF001

    store._entries[("k1", "expiring")] = ("sha256:old", 9)  # noqa: SLF001
    assert (
        store.check_and_mark(
            kid="k1",
            nonce="expiring",
            scope_hash="sha256:new",
            expires_at=25,
            replay_mode="single_use",
        )
        == "ok"
    )
    assert store._entries[("k1", "expiring")] == ("sha256:new", 25)  # noqa: SLF001


def test_replay_store_idempotent_scope_mismatch() -> None:
    store = _InMemoryReplayStore()
    assert (
        store.check_and_mark(
            kid="k1",
            nonce="n1",
            scope_hash="sha256:a",
            expires_at=int(time.time()) + 30,
            replay_mode="idempotent",
        )
        == "ok"
    )
    assert (
        store.check_and_mark(
            kid="k1",
            nonce="n1",
            scope_hash="sha256:b",
            expires_at=int(time.time()) + 30,
            replay_mode="idempotent",
        )
        == "nonce_scope_mismatch"
    )


class _FakeRedisClient:
    def __init__(self) -> None:
        self.entries: dict[str, str] = {}

    def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
        if ex is not None and int(ex) <= 0:
            return False
        if nx and key in self.entries:
            return False
        self.entries[key] = str(value)
        return True

    def get(self, key: str) -> str | None:
        return self.entries.get(key)


def test_redis_replay_store_single_use_rejects_second_nonce_use() -> None:
    store = _RedisReplayStore(_FakeRedisClient(), prefix="aetherya:test")
    now = int(time.time())

    first = store.check_and_mark(
        kid="k1",
        nonce="n1",
        scope_hash="sha256:abc",
        expires_at=now + 60,
        replay_mode="single_use",
    )
    second = store.check_and_mark(
        kid="k1",
        nonce="n1",
        scope_hash="sha256:abc",
        expires_at=now + 60,
        replay_mode="single_use",
    )

    assert first == "ok"
    assert second == "replay_detected"


def test_redis_replay_store_idempotent_accepts_same_nonce_same_scope() -> None:
    store = _RedisReplayStore(_FakeRedisClient(), prefix="aetherya:test")
    now = int(time.time())

    first = store.check_and_mark(
        kid="k1",
        nonce="same-nonce",
        scope_hash="sha256:scope-a",
        expires_at=now + 60,
        replay_mode="idempotent",
    )
    second = store.check_and_mark(
        kid="k1",
        nonce="same-nonce",
        scope_hash="sha256:scope-a",
        expires_at=now + 60,
        replay_mode="idempotent",
    )
    mismatch = store.check_and_mark(
        kid="k1",
        nonce="other-nonce",
        scope_hash="sha256:scope-a",
        expires_at=now + 60,
        replay_mode="idempotent",
    )

    assert first == "ok"
    assert second == "ok"
    assert mismatch == "nonce_scope_mismatch"


def test_confirmation_gate_redis_requires_url_env_when_enabled(
    monkeypatch,  # noqa: ANN001
) -> None:
    monkeypatch.delenv("AETHERYA_TEST_REPLAY_URL", raising=False)

    with pytest.raises(RuntimeError, match="replay_store=redis"):
        make_confirmation_gate(
            signed_proof_enabled=True,
            signed_proof_key_env="AETHERYA_TEST_SIGN_KEY",
            signed_proof_replay_store="redis",
            signed_proof_replay_redis_url_env="AETHERYA_TEST_REPLAY_URL",
        )


def test_confirmation_gate_builds_redis_store_from_env(
    monkeypatch,  # noqa: ANN001
) -> None:
    import aetherya.confirmation_gate as confirmation_gate_module

    class _FakeRedisModule:
        @staticmethod
        def from_url(url: str, decode_responses: bool = True) -> _FakeRedisClient:
            assert url == "redis://unit-test:6379/0"
            assert decode_responses is True
            return _FakeRedisClient()

    monkeypatch.setenv("AETHERYA_TEST_SIGN_KEY", "redis-build-key")
    monkeypatch.setenv("AETHERYA_TEST_REPLAY_URL", "redis://unit-test:6379/0")
    monkeypatch.setattr(
        confirmation_gate_module.importlib,
        "import_module",
        lambda name: _FakeRedisModule,
    )
    confirmation_gate_module._REPLAY_STORES.clear()  # noqa: SLF001

    gate = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_SIGN_KEY",
        signed_proof_replay_store="redis",
        signed_proof_replay_redis_url_env="AETHERYA_TEST_REPLAY_URL",
        signed_proof_replay_redis_prefix="aetherya:test:redis",
    )
    gate_cached = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_SIGN_KEY",
        signed_proof_replay_store="redis",
        signed_proof_replay_redis_url_env="AETHERYA_TEST_REPLAY_URL",
        signed_proof_replay_redis_prefix="aetherya:test:redis",
    )

    assert isinstance(gate.replay_store, confirmation_gate_module._RedisReplayStore)
    assert gate_cached.replay_store is gate.replay_store
    confirmation_gate_module._REPLAY_STORES.clear()  # noqa: SLF001


def test_confirmation_gate_redis_shared_store_blocks_second_process(
    monkeypatch,  # noqa: ANN001
) -> None:
    monkeypatch.setenv("AETHERYA_TEST_REPLAY_KEY", "replay-key")
    fake_redis = _FakeRedisClient()
    store_a = _RedisReplayStore(fake_redis, prefix="aetherya:shared")
    store_b = _RedisReplayStore(fake_redis, prefix="aetherya:shared")

    gate_a = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_REPLAY_KEY",
        signed_proof_replay_mode="single_use",
        replay_store=store_a,
    )
    gate_b = make_confirmation_gate(
        signed_proof_enabled=True,
        signed_proof_key_env="AETHERYA_TEST_REPLAY_KEY",
        signed_proof_replay_mode="single_use",
        replay_store=store_b,
    )

    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        target="/tmp",
        parameters={
            "operation": "write",
            "path": "/tmp/a.txt",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved by operator",
        },
    )
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="replay-key",
        kid="k1",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=int(time.time()),
        nonce="sharednonce",
        exclude_params=excluded,
    )
    action.parameters["confirm_proof"] = proof

    first = gate_a.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    second = gate_b.evaluate(
        action=action,
        aggregate=make_aggregate(RiskDecision.REQUIRE_CONFIRM),
        actor="robert",
    )
    assert first is not None and first["confirmed"] is True
    assert second is not None and second["confirmed"] is False
    assert "confirmation_proof_replay_rejected" in second["tags"]


def test_redis_replay_store_decode_branches_for_none_and_bytes() -> None:
    class _MissingScopeRedis:
        def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
            return False

        def get(self, key: str) -> None:
            return None

    class _BytesScopeRedis:
        def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
            return False

        def get(self, key: str) -> bytes:
            return b"k1|n1|1700000100"

    missing_store = _RedisReplayStore(_MissingScopeRedis(), prefix="aetherya:test")
    bytes_store = _RedisReplayStore(_BytesScopeRedis(), prefix="aetherya:test")

    result_missing = missing_store.check_and_mark(
        kid="k1",
        nonce="n1",
        scope_hash="sha256:scope-a",
        expires_at=int(time.time()) + 60,
        replay_mode="idempotent",
    )
    result_bytes = bytes_store.check_and_mark(
        kid="k1",
        nonce="n1",
        scope_hash="sha256:scope-a",
        expires_at=int(time.time()) + 60,
        replay_mode="idempotent",
    )
    assert result_missing == "nonce_scope_mismatch"
    assert result_bytes == "ok"


def test_redis_client_from_url_fallback_paths(
    monkeypatch,  # noqa: ANN001
) -> None:
    import aetherya.confirmation_gate as confirmation_gate_module

    class _FallbackRedisClass:
        @staticmethod
        def from_url(url: str, decode_responses: bool = True) -> str:
            assert url == "redis://fallback:6379/0"
            assert decode_responses is True
            return "redis-client-fallback"

    class _FallbackModule:
        from_url = None
        Redis = _FallbackRedisClass

    class _NoRedisModule:
        from_url = None
        Redis = None

    class _NoFromUrlRedisClass:
        pass

    class _NoFromUrlModule:
        from_url = None
        Redis = _NoFromUrlRedisClass

    monkeypatch.setattr(
        confirmation_gate_module.importlib,
        "import_module",
        lambda name: _FallbackModule,
    )
    assert (
        confirmation_gate_module._redis_client_from_url("redis://fallback:6379/0")
        == "redis-client-fallback"
    )

    monkeypatch.setattr(
        confirmation_gate_module.importlib,
        "import_module",
        lambda name: _NoRedisModule,
    )
    with pytest.raises(RuntimeError, match="does not expose Redis client"):
        confirmation_gate_module._redis_client_from_url("redis://missing:6379/0")

    monkeypatch.setattr(
        confirmation_gate_module.importlib,
        "import_module",
        lambda name: _NoFromUrlModule,
    )
    with pytest.raises(RuntimeError, match="does not support from_url"):
        confirmation_gate_module._redis_client_from_url("redis://missing-from-url:6379/0")
