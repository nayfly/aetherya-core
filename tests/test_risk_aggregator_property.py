from __future__ import annotations

from random import Random

from aetherya.config import AggregatorConfig, ModeConfig, ModeThresholds
from aetherya.risk import RiskAggregator, RiskDecision, RiskSignal


def _make_modes() -> dict[str, ModeConfig]:
    return {
        "operative": ModeConfig(
            default_state="allow",
            thresholds=ModeThresholds(deny_at=80, confirm_at=50, log_only_at=0),
        )
    }


def _make_sources() -> list[str]:
    return [
        "execution_gate",
        "capability_gate",
        "jailbreak_guard",
        "procedural_guard",
        "constitution",
    ]


def test_risk_aggregator_property_randomized_extremes_are_deterministic() -> None:
    rng = Random(1337)
    agg = RiskAggregator(
        cfg=AggregatorConfig(
            weights={
                "execution_gate": 1.0,
                "capability_gate": 1.2,
                "jailbreak_guard": 0.8,
                "procedural_guard": 1.0,
                "constitution": 1.1,
            },
            hard_deny_if=[],
        ),
        modes=_make_modes(),
    )
    sources = _make_sources()

    for _ in range(3000):
        signal_count = rng.randrange(0, 25)
        signals: list[RiskSignal] = []
        for idx in range(signal_count):
            source = sources[rng.randrange(len(sources))]
            score = rng.randrange(-300, 301)
            confidence = rng.uniform(-2.5, 2.5)
            tags: list[str] = []
            if rng.random() < 0.1:
                tags.append("tag:extreme")
            signals.append(
                RiskSignal(
                    source=source,
                    score=score,
                    confidence=confidence,
                    reason=f"r{idx}",
                    tags=tags,
                )
            )

        result_a = agg.aggregate(signals, mode="operative")
        result_b = agg.aggregate(signals, mode="operative")
        assert result_a.total_score == result_b.total_score
        assert result_a.decision == result_b.decision
        assert result_a.reasons == result_b.reasons
        assert result_a.breakdown == signals
        assert isinstance(result_a.decision, RiskDecision)
        assert isinstance(result_a.total_score, int)


def test_risk_aggregator_property_critical_tag_always_hard_deny() -> None:
    rng = Random(2026)
    agg = RiskAggregator(
        cfg=AggregatorConfig(
            weights={"constitution": 1.0},
            hard_deny_if=["critical_tag_detected"],
        ),
        modes=_make_modes(),
    )

    for _ in range(1000):
        score = rng.randrange(-500, 501)
        confidence = rng.uniform(-3.0, 3.0)
        signals = [
            RiskSignal(
                source="constitution",
                score=score,
                confidence=confidence,
                reason="random",
                tags=["critical_tag_detected"],
            )
        ]
        result = agg.aggregate(signals, mode="operative")
        assert result.decision == RiskDecision.HARD_DENY
