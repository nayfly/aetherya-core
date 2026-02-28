from __future__ import annotations

from aetherya.config import AggregatorConfig, ModeConfig, ModeThresholds
from aetherya.risk import RiskAggregator, RiskDecision, RiskSignal


def make_modes(default_state: str = "allow") -> dict[str, ModeConfig]:
    return {
        "operative": ModeConfig(
            default_state=default_state,
            thresholds=ModeThresholds(deny_at=80, confirm_at=50, log_only_at=0),
        )
    }


def test_risk_aggregator_invalid_weight_falls_back_to_default() -> None:
    cfg = AggregatorConfig(weights={"constitution": "bad"}, hard_deny_if=[])  # type: ignore[dict-item]
    agg = RiskAggregator(cfg=cfg, modes=make_modes())
    signals = [RiskSignal(source="constitution", score=40, confidence=1.0, reason="x", tags=[])]
    result = agg.aggregate(signals, mode="operative")
    assert result.total_score == 40
    assert result.decision == RiskDecision.LOG_ONLY


def test_risk_aggregator_hard_deny_by_source_rule() -> None:
    cfg = AggregatorConfig(weights={}, hard_deny_if=["source:jailbreak_guard"])
    agg = RiskAggregator(cfg=cfg, modes=make_modes())
    signals = [RiskSignal(source="jailbreak_guard", score=1, confidence=1.0, reason="x", tags=[])]
    result = agg.aggregate(signals, mode="operative")
    assert result.decision == RiskDecision.HARD_DENY


def test_risk_aggregator_ignores_empty_hard_deny_rule() -> None:
    cfg = AggregatorConfig(weights={}, hard_deny_if=[" "])
    agg = RiskAggregator(cfg=cfg, modes=make_modes())
    signals = [RiskSignal(source="constitution", score=0, confidence=1.0, reason="", tags=[])]
    result = agg.aggregate(signals, mode="operative")
    assert result.decision == RiskDecision.ALLOW


def test_risk_aggregator_unknown_default_state_falls_back_to_deny() -> None:
    cfg = AggregatorConfig(weights={}, hard_deny_if=[])
    agg = RiskAggregator(cfg=cfg, modes=make_modes(default_state="mystery"))
    result = agg.aggregate([], mode="operative")
    assert result.decision == RiskDecision.DENY


def test_risk_aggregator_unknown_hard_deny_rule_is_ignored() -> None:
    cfg = AggregatorConfig(weights={}, hard_deny_if=["unknown_rule"])
    agg = RiskAggregator(cfg=cfg, modes=make_modes())
    signals = [RiskSignal(source="constitution", score=10, confidence=1.0, reason="x", tags=[])]
    result = agg.aggregate(signals, mode="operative")
    assert result.decision == RiskDecision.LOG_ONLY
