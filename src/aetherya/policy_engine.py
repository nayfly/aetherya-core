from __future__ import annotations

from enum import StrEnum
from typing import Any, Final

from aetherya.modes import Mode
from aetherya.risk import RiskDecision


class DecisionState(StrEnum):
    HARD_DENY = "hard_deny"
    DENY = "deny"
    ESCALATE = "escalate"
    LOG_ONLY = "log_only"
    ALLOW = "allow"


# Jerarquía inmutable de severidad (más restrictiva -> menos restrictiva).
DECISION_HIERARCHY: Final[tuple[DecisionState, ...]] = (
    DecisionState.HARD_DENY,
    DecisionState.DENY,
    DecisionState.ESCALATE,
    DecisionState.LOG_ONLY,
    DecisionState.ALLOW,
)
_DECISION_RANK: Final[dict[DecisionState, int]] = {
    DecisionState.ALLOW: 0,
    DecisionState.LOG_ONLY: 1,
    DecisionState.ESCALATE: 2,
    DecisionState.DENY: 3,
    DecisionState.HARD_DENY: 4,
}


def decision_rank(state: DecisionState) -> int:
    return _DECISION_RANK[state]


def strictest_state(states: list[DecisionState]) -> DecisionState:
    if not states:
        raise ValueError("states must be non-empty")
    return max(states, key=decision_rank)


class PolicyEngine:
    def evaluate(self, decision: Any, mode: Mode) -> DecisionState:
        if not isinstance(mode, Mode):
            return DecisionState.ESCALATE

        if not isinstance(decision, RiskDecision):
            return DecisionState.ESCALATE  # ← test exige esto

        # Primero respetamos el riesgo
        if decision == RiskDecision.HARD_DENY:
            return DecisionState.HARD_DENY

        if decision == RiskDecision.DENY:
            return DecisionState.DENY

        if decision == RiskDecision.REQUIRE_CONFIRM:
            return DecisionState.ESCALATE

        if decision == RiskDecision.LOG_ONLY:
            return DecisionState.LOG_ONLY

        # El default por modo se resuelve en RiskAggregator vía config.
        return DecisionState.ALLOW
