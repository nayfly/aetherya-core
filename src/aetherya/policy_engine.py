from __future__ import annotations

from enum import StrEnum

from aetherya.modes import Mode


class DecisionState(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"  # pedir confirmación humana
    LOG_ONLY = "log_only"  # consultivo, no ejecuta


class PolicyEngine:
    def evaluate(self, constitution_result: dict, mode: Mode) -> DecisionState:
        # Si la Constitución prohíbe, se deniega siempre.
        if not constitution_result.get("allowed", False):
            return DecisionState.DENY

        risk = int(constitution_result.get("risk_score", 0))

        # Reglas por modo
        if mode == Mode.CONSULTIVE:
            # En consultivo nunca ejecutas herramientas. Solo “permitir respuesta”.
            return DecisionState.LOG_ONLY

        if mode == Mode.OPERATIVE:
            # Operativo: permites solo si riesgo bajo.
            if risk <= 20:
                return DecisionState.ALLOW
            return DecisionState.ESCALATE

        # Default seguro
        return DecisionState.ESCALATE
