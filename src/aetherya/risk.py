from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from aetherya.config import AggregatorConfig, ModeConfig


class RiskDecision(StrEnum):
    HARD_DENY = "hard_deny"
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

    _DEFAULT_DECISION_BY_STATE: Final[dict[str, RiskDecision]] = {
        "allow": RiskDecision.ALLOW,
        "log_only": RiskDecision.LOG_ONLY,
        "require_confirm": RiskDecision.REQUIRE_CONFIRM,
        "deny": RiskDecision.DENY,
        "hard_deny": RiskDecision.HARD_DENY,
    }

    def _weight_for_source(self, source: str) -> float:
        raw = self.cfg.weights.get(source, 1.0)
        try:
            weight = float(raw)
        except (TypeError, ValueError):
            return 1.0
        return max(0.0, weight)

    def _tags(self, signals: list[RiskSignal]) -> set[str]:
        tags: set[str] = set()
        for s in signals:
            for tag in s.tags:
                tags.add(tag.strip().lower())
        return tags

    def _matches_hard_deny_rule(self, rule: str, signals: list[RiskSignal]) -> bool:
        r = rule.strip().lower()
        if not r:
            return False

        tags = self._tags(signals)

        if r == "critical_tag_detected":
            return "critical_tag_detected" in tags

        if r.startswith("tag:"):
            target_tag = r.split(":", 1)[1].strip()
            return bool(target_tag) and target_tag in tags

        if r.startswith("source:"):
            source = r.split(":", 1)[1].strip()
            return bool(source) and any(s.source == source for s in signals)

        return False

    def _is_hard_deny(self, signals: list[RiskSignal]) -> bool:
        for rule in self.cfg.hard_deny_if:
            if self._matches_hard_deny_rule(rule, signals):
                return True
        return False

    def _default_decision(self, mode: str) -> RiskDecision:
        mode_cfg = self.modes[mode]
        raw_default = getattr(mode_cfg, "default_state", "allow")
        default_state = str(raw_default).strip().lower()
        return self._DEFAULT_DECISION_BY_STATE.get(default_state, RiskDecision.DENY)

    def aggregate(self, signals: list[RiskSignal], mode: str) -> RiskAggregate:
        mode_cfg = self.modes[mode]
        thresholds = mode_cfg.thresholds
        deny_threshold = thresholds.deny_at
        confirm_threshold = thresholds.confirm_at
        log_only_threshold = thresholds.log_only_at

        weighted = [
            (int(round(s.score * s.confidence * self._weight_for_source(s.source))), s)
            for s in signals
        ]
        total = sum(w for w, _ in weighted)

        top_signal = max(weighted, key=lambda x: x[0])[1] if weighted else None
        reasons = [s.reason for _, s in weighted if s.reason]

        if self._is_hard_deny(signals):
            decision = RiskDecision.HARD_DENY
        elif total >= deny_threshold:
            decision = RiskDecision.DENY
        elif total >= confirm_threshold:
            decision = RiskDecision.REQUIRE_CONFIRM
        elif total >= log_only_threshold and total > 0:
            decision = RiskDecision.LOG_ONLY
        else:
            decision = self._default_decision(mode)

        return RiskAggregate(
            total_score=total,
            decision=decision,
            reasons=reasons,
            breakdown=signals,
            top_signal=top_signal,
        )
