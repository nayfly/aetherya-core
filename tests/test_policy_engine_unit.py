from typing import Any, cast

from aetherya.modes import Mode
from aetherya.policy_engine import DecisionState, PolicyEngine
from aetherya.risk import RiskDecision


def test_policy_engine_consultive_keeps_deny_as_deny() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.DENY, mode=Mode.CONSULTIVE)
    assert state == DecisionState.DENY


def test_policy_engine_maps_deny_to_deny() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.DENY, mode=Mode.OPERATIVE)
    assert state == DecisionState.DENY


def test_policy_engine_maps_require_confirm_to_escalate() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.REQUIRE_CONFIRM, mode=Mode.OPERATIVE)
    assert state == DecisionState.ESCALATE


def test_policy_engine_maps_log_only_to_log_only() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.LOG_ONLY, mode=Mode.OPERATIVE)
    assert state == DecisionState.LOG_ONLY


def test_policy_engine_maps_allow_to_allow() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.ALLOW, mode=Mode.OPERATIVE)
    assert state == DecisionState.ALLOW


def test_policy_engine_unknown_decision_fails_closed_to_escalate() -> None:
    engine = PolicyEngine()
    weird: Any = "SOMETHING_NEW"
    state = engine.evaluate(decision=weird, mode=Mode.OPERATIVE)
    assert state == DecisionState.ESCALATE


def test_policy_engine_unknown_mode_fails_closed_to_escalate() -> None:
    engine = PolicyEngine()
    weird_mode = cast(Mode, "UNKNOWN_MODE")
    state = engine.evaluate(decision=RiskDecision.ALLOW, mode=weird_mode)
    assert state == DecisionState.ESCALATE
