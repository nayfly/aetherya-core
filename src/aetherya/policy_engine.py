from __future__ import annotations

from enum import StrEnum
from typing import Any

from aetherya.modes import Mode


class DecisionState(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"  # pedir confirmación humana
    LOG_ONLY = "log_only"  # consultivo, no ejecuta


class PolicyEngine:
    def _parse_risk(self, constitution_result: dict[str, Any]) -> int | None:
        raw = constitution_result.get("risk_score", 0)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    def evaluate(self, constitution_result: dict[str, Any], mode: Mode) -> DecisionState:
        if not constitution_result.get("allowed", False):
            return DecisionState.DENY

        if mode == Mode.CONSULTIVE:
            return DecisionState.LOG_ONLY

        risk = self._parse_risk(constitution_result)
        if risk is None:
            return DecisionState.ESCALATE  # fail-closed

        if mode == Mode.OPERATIVE:
            if risk <= 20:
                return DecisionState.ALLOW
            return DecisionState.ESCALATE

        return DecisionState.ESCALATE
