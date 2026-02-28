from __future__ import annotations

import re
from typing import TypedDict

from aetherya.actions import ActionRequest
from aetherya.config import ConfirmationConfig
from aetherya.risk import RiskAggregate, RiskDecision


class ConfirmationOutcome(TypedDict, total=False):
    required: bool
    confirmed: bool
    reason: str
    tags: list[str]
    override_decision: str


class ConfirmationGate:
    def __init__(self, cfg: ConfirmationConfig) -> None:
        self.cfg = cfg

    def _requires_confirmation(self, action: ActionRequest, aggregate: RiskAggregate) -> bool:
        require = self.cfg.require_for
        if aggregate.decision.value in require.decisions:
            return True

        tool = (action.tool or "").strip().lower()
        if tool and tool in require.tools:
            return True

        op_raw = action.parameters.get("operation")
        operation = str(op_raw).strip().lower() if op_raw is not None else ""
        if operation and operation in require.operations:
            return True

        if aggregate.total_score >= require.min_risk_score and require.min_risk_score > 0:
            return True

        return False

    def _token_is_valid(self, token: str) -> bool:
        return re.fullmatch(self.cfg.evidence.token_pattern, token) is not None

    def evaluate(
        self, *, action: ActionRequest, aggregate: RiskAggregate
    ) -> ConfirmationOutcome | None:
        if not self.cfg.enabled:
            return None

        if action.intent != "operate":
            return None

        if not self._requires_confirmation(action, aggregate):
            return None

        token_key = self.cfg.evidence.token_param
        context_key = self.cfg.evidence.context_param

        token_raw = action.parameters.get(token_key)
        context_raw = action.parameters.get(context_key)

        if token_raw is None or context_raw is None:
            return {
                "required": True,
                "confirmed": False,
                "reason": "strong confirmation evidence is missing",
                "tags": ["confirmation_required", "confirmation_missing"],
            }

        token = str(token_raw).strip().lower()
        context = str(context_raw).strip()

        if not self._token_is_valid(token):
            return {
                "required": True,
                "confirmed": False,
                "reason": "strong confirmation token is invalid",
                "tags": ["confirmation_required", "confirmation_invalid_token"],
            }

        if len(context) < self.cfg.evidence.min_context_length:
            return {
                "required": True,
                "confirmed": False,
                "reason": "strong confirmation context is too short",
                "tags": ["confirmation_required", "confirmation_context_too_short"],
            }

        outcome: ConfirmationOutcome = {
            "required": True,
            "confirmed": True,
            "reason": "strong confirmation validated",
            "tags": ["confirmation_validated"],
        }

        if aggregate.decision == RiskDecision.REQUIRE_CONFIRM:
            outcome["override_decision"] = self.cfg.on_confirmed

        return outcome
