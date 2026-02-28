from __future__ import annotations

from enum import StrEnum
from typing import Any

from aetherya.modes import Mode
from aetherya.risk import RiskDecision


class DecisionState(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    LOG_ONLY = "log_only"


class PolicyEngine:
    def evaluate(self, decision: Any, mode: Mode) -> DecisionState:
        if not isinstance(mode, Mode):
            return DecisionState.ESCALATE

        if not isinstance(decision, RiskDecision):
            return DecisionState.ESCALATE  # ← test exige esto

        # Primero respetamos el riesgo
        if decision == RiskDecision.DENY:
            return DecisionState.DENY

        if decision == RiskDecision.REQUIRE_CONFIRM:
            return DecisionState.ESCALATE

        if decision == RiskDecision.LOG_ONLY:
            return DecisionState.LOG_ONLY

        # Solo aquí afecta el modo
        if mode == Mode.CONSULTIVE:
            return DecisionState.LOG_ONLY

        return DecisionState.ALLOW
