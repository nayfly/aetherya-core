from typing import Any, cast

import pytest

from aetherya.modes import Mode
from aetherya.policy_engine import (
    DECISION_HIERARCHY,
    DecisionState,
    PolicyEngine,
    decision_rank,
    strictest_state,
)
from aetherya.risk import RiskDecision


def test_policy_engine_maps_hard_deny_to_hard_deny() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.HARD_DENY, mode=Mode.OPERATIVE)
    assert state == DecisionState.HARD_DENY


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


def test_policy_engine_consultive_allow_stays_allow() -> None:
    engine = PolicyEngine()
    state = engine.evaluate(decision=RiskDecision.ALLOW, mode=Mode.CONSULTIVE)
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


def test_decision_hierarchy_is_immutable_contract() -> None:
    assert DECISION_HIERARCHY == (
        DecisionState.HARD_DENY,
        DecisionState.DENY,
        DecisionState.ESCALATE,
        DecisionState.LOG_ONLY,
        DecisionState.ALLOW,
    )
    assert decision_rank(DecisionState.HARD_DENY) > decision_rank(DecisionState.DENY)
    assert decision_rank(DecisionState.DENY) > decision_rank(DecisionState.ESCALATE)
    assert decision_rank(DecisionState.ESCALATE) > decision_rank(DecisionState.LOG_ONLY)
    assert decision_rank(DecisionState.LOG_ONLY) > decision_rank(DecisionState.ALLOW)


def test_strictest_state_returns_most_restrictive() -> None:
    state = strictest_state(
        [DecisionState.LOG_ONLY, DecisionState.ALLOW, DecisionState.DENY, DecisionState.ESCALATE]
    )
    assert state == DecisionState.DENY


def test_strictest_state_rejects_empty_list() -> None:
    with pytest.raises(ValueError, match="states must be non-empty"):
        strictest_state([])
