from __future__ import annotations

from aetherya.explainability import ExplainabilityEngine
from aetherya.risk import RiskAggregate, RiskDecision, RiskSignal


def make_aggregate(
    *, total: int, decision: RiskDecision, signals: list[RiskSignal]
) -> RiskAggregate:
    top_signal = max(signals, key=lambda s: s.score) if signals else None
    return RiskAggregate(
        total_score=total,
        decision=decision,
        reasons=[s.reason for s in signals if s.reason],
        breakdown=signals,
        top_signal=top_signal,
    )


def test_explainability_builds_weighted_contributors_graph() -> None:
    signals = [
        RiskSignal(source="constitution", score=40, confidence=1.0, reason="policy"),
        RiskSignal(source="procedural_guard", score=20, confidence=0.5, reason="guard"),
    ]
    aggregate = make_aggregate(total=50, decision=RiskDecision.REQUIRE_CONFIRM, signals=signals)
    graph = ExplainabilityEngine().build(
        signals=signals,
        aggregate=aggregate,
        mode="operative",
        weights={"constitution": 1.0, "procedural_guard": 1.0},
        thresholds={"deny_at": 80, "confirm_at": 50, "log_only_at": 0},
        aggregate_decision=aggregate.decision.value,
        effective_risk_decision=aggregate.decision.value,
        state="escalate",
        allowed=False,
        reason="escalate: policy",
        violated_principle="Caution",
        confirmation=None,
    )

    assert graph["summary"]["state"] == "escalate"
    assert graph["summary"]["top_contributor"] == "constitution"
    assert len(graph["contributors"]) == 2
    assert graph["contributors"][0]["weighted_score"] == 40
    assert graph["contributors"][1]["weighted_score"] == 10
    assert graph["graph"]["nodes"]
    assert graph["graph"]["edges"]


def test_explainability_adds_confirmation_path_when_present() -> None:
    signals = [RiskSignal(source="constitution", score=55, confidence=1.0, reason="sensitive")]
    aggregate = make_aggregate(total=55, decision=RiskDecision.REQUIRE_CONFIRM, signals=signals)
    graph = ExplainabilityEngine().build(
        signals=signals,
        aggregate=aggregate,
        mode="operative",
        weights={"constitution": 1.0},
        thresholds={"deny_at": 80, "confirm_at": 50, "log_only_at": 0},
        aggregate_decision=aggregate.decision.value,
        effective_risk_decision="allow",
        state="allow",
        allowed=True,
        reason="allow: strong confirmation validated",
        violated_principle="Caution",
        confirmation={
            "required": True,
            "confirmed": True,
            "reason": "strong confirmation validated",
            "tags": ["confirmation_validated"],
            "override_decision": "allow",
        },
    )

    node_types = {node["type"] for node in graph["graph"]["nodes"]}
    assert "confirmation_gate" in node_types
    assert any(edge["type"] == "checked_by_confirmation" for edge in graph["graph"]["edges"])


def test_explainability_handles_zero_total_score_without_division_error() -> None:
    signals = [RiskSignal(source="constitution", score=0, confidence=1.0, reason="none")]
    aggregate = make_aggregate(total=0, decision=RiskDecision.ALLOW, signals=signals)
    graph = ExplainabilityEngine().build(
        signals=signals,
        aggregate=aggregate,
        mode="consultive",
        weights={"constitution": 1.0},
        thresholds={"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
        aggregate_decision=aggregate.decision.value,
        effective_risk_decision=aggregate.decision.value,
        state="allow",
        allowed=True,
        reason="allow: ok",
        violated_principle=None,
        confirmation=None,
    )
    assert graph["contributors"][0]["contribution_ratio"] == 0.0


def test_explainability_invalid_weight_falls_back_to_default() -> None:
    signals = [RiskSignal(source="constitution", score=10, confidence=1.0, reason="x")]
    aggregate = make_aggregate(total=10, decision=RiskDecision.LOG_ONLY, signals=signals)
    graph = ExplainabilityEngine().build(
        signals=signals,
        aggregate=aggregate,
        mode="consultive",
        weights={"constitution": "bad"},  # type: ignore[dict-item]
        thresholds={},
        aggregate_decision=aggregate.decision.value,
        effective_risk_decision=aggregate.decision.value,
        state="log_only",
        allowed=False,
        reason="log_only: x",
        violated_principle="Caution",
        confirmation=None,
    )
    assert graph["contributors"][0]["weight"] == 1.0
