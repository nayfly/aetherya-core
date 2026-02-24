from typing import cast

from aetherya.modes import Mode
from aetherya.policy_engine import DecisionState, PolicyEngine


def test_policy_engine_denies_when_not_allowed() -> None:
    engine = PolicyEngine()
    state = engine.evaluate({"allowed": False, "risk_score": 0}, mode=Mode.OPERATIVE)
    assert state == DecisionState.DENY


def test_policy_engine_operational_missing_risk_defaults_to_zero_allows() -> None:
    engine = PolicyEngine()
    state = engine.evaluate({"allowed": True}, mode=Mode.OPERATIVE)
    assert state == DecisionState.ALLOW


def test_policy_engine_risk_string_is_castable() -> None:
    engine = PolicyEngine()
    state = engine.evaluate({"allowed": True, "risk_score": "20"}, mode=Mode.OPERATIVE)
    assert state == DecisionState.ALLOW


def test_policy_engine_operational_escalates_when_risk_above_threshold() -> None:
    engine = PolicyEngine()
    state = engine.evaluate({"allowed": True, "risk_score": 21}, mode=Mode.OPERATIVE)
    assert state == DecisionState.ESCALATE


def test_policy_engine_consultive_is_always_log_only_when_allowed() -> None:
    engine = PolicyEngine()
    state = engine.evaluate({"allowed": True, "risk_score": 999}, mode=Mode.CONSULTIVE)
    assert state == DecisionState.LOG_ONLY


def test_policy_engine_unknown_mode_falls_back_to_safe_default() -> None:
    engine = PolicyEngine()
    weird_mode = cast(Mode, "UNKNOWN_MODE")
    state = engine.evaluate({"allowed": True, "risk_score": 0}, mode=weird_mode)
    assert state == DecisionState.ESCALATE


def test_policy_engine_risk_invalid_string_fails_closed() -> None:
    engine = PolicyEngine()
    state = engine.evaluate({"allowed": True, "risk_score": "nope"}, mode=Mode.OPERATIVE)
    assert state == DecisionState.ESCALATE
