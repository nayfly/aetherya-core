from __future__ import annotations

from aetherya.actions import ActionRequest
from aetherya.config import (
    ConfirmationConfig,
    ConfirmationEvidenceConfig,
    ConfirmationRequireConfig,
)
from aetherya.confirmation_gate import ConfirmationGate
from aetherya.risk import RiskAggregate, RiskDecision, RiskSignal


def make_confirmation_gate(
    enabled: bool = True,
    *,
    decisions: list[str] | None = None,
    tools: list[str] | None = None,
    operations: list[str] | None = None,
    min_risk_score: int = 0,
    on_confirmed: str = "allow",
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
        ),
    )
    return ConfirmationGate(cfg)


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
