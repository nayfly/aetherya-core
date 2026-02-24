from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from aetherya.config import AggregatorConfig, ModeConfig


class RiskDecision(StrEnum):
    ALLOW = "allow"
    LOG_ONLY = "log_only"
    REQUIRE_CONFIRM = "require_confirm"
    DENY = "deny"


@dataclass(frozen=True)
class RiskSignal:
    source: str
    score: int
    confidence: float = 1.0
    reason: str = ""
    tags: list[str] = field(default_factory=list)
    violated_principle: str | None = None


@dataclass(frozen=True)
class RiskAggregate:
    total_score: int
    decision: RiskDecision
    reasons: list[str]
    breakdown: list[RiskSignal]
    top_signal: RiskSignal | None


class RiskAggregator:
    def __init__(self, cfg: AggregatorConfig, modes: dict[str, ModeConfig]) -> None:
        self.cfg = cfg
        self.modes = modes

    def aggregate(self, signals: list[RiskSignal], mode: str) -> RiskAggregate:
        thresholds = self.modes[mode].thresholds
        deny_threshold = thresholds.deny_at
        confirm_threshold = thresholds.confirm_at

        weighted = [(int(round(s.score * s.confidence)), s) for s in signals]
        total = sum(w for w, _ in weighted)

        top_signal = max(weighted, key=lambda x: x[0])[1] if weighted else None
        reasons = [s.reason for _, s in weighted if s.reason]

        if total >= deny_threshold:
            decision = RiskDecision.DENY
        elif total >= confirm_threshold:
            decision = RiskDecision.REQUIRE_CONFIRM
        elif total > 0:
            decision = RiskDecision.LOG_ONLY
        else:
            decision = RiskDecision.ALLOW

        return RiskAggregate(
            total_score=total,
            decision=decision,
            reasons=reasons,
            breakdown=signals,
            top_signal=top_signal,
        )
