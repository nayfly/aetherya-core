from __future__ import annotations

import os
import re
from typing import TypedDict

from aetherya.actions import ActionRequest
from aetherya.approval_proof import ApprovalProofError, verify_approval_proof
from aetherya.config import ConfirmationConfig
from aetherya.risk import RiskAggregate, RiskDecision


class ConfirmationOutcome(TypedDict, total=False):
    required: bool
    confirmed: bool
    reason: str
    tags: list[str]
    override_decision: str
    proof_required: bool
    proof_valid: bool
    proof_expires_at: int
    proof_scope_hash: str


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
        self, *, action: ActionRequest, aggregate: RiskAggregate, actor: str = "unknown"
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

        signed_proof_cfg = self.cfg.evidence.signed_proof
        proof_expires_at: int | None = None
        proof_scope_hash: str | None = None
        proof_tags: list[str] = []
        if signed_proof_cfg.enabled:
            proof_key = signed_proof_cfg.proof_param
            proof_raw = action.parameters.get(proof_key)
            if proof_raw is None or not str(proof_raw).strip():
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": "out-of-band approval proof is missing",
                    "tags": ["confirmation_required", "confirmation_proof_missing"],
                    "proof_required": True,
                    "proof_valid": False,
                }

            verifier_secret = os.getenv(signed_proof_cfg.key_env, "").strip()
            if not verifier_secret:
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": "approval verifier key is not configured",
                    "tags": ["confirmation_required", "confirmation_proof_key_missing"],
                    "proof_required": True,
                    "proof_valid": False,
                }

            exclude_keys = {name for name in action.parameters if str(name).startswith("confirm_")}
            try:
                verification = verify_approval_proof(
                    secret=verifier_secret,
                    proof=str(proof_raw),
                    actor=str(actor),
                    action=action,
                    clock_skew_sec=signed_proof_cfg.clock_skew_sec,
                    max_valid_for_sec=signed_proof_cfg.max_valid_for_sec,
                    exclude_params=exclude_keys,
                )
            except ApprovalProofError as exc:
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": f"out-of-band approval proof is invalid ({exc.code})",
                    "tags": [
                        "confirmation_required",
                        "confirmation_proof_invalid",
                        f"confirmation_proof_{exc.code}",
                    ],
                    "proof_required": True,
                    "proof_valid": False,
                }

            proof_expires_at = verification.expires_at
            proof_scope_hash = verification.scope_hash
            proof_tags.append("confirmation_proof_validated")

        outcome: ConfirmationOutcome = {
            "required": True,
            "confirmed": True,
            "reason": "strong confirmation validated",
            "tags": ["confirmation_validated", *proof_tags],
        }
        if signed_proof_cfg.enabled:
            outcome["proof_required"] = True
            outcome["proof_valid"] = True
        if proof_expires_at is not None:
            outcome["proof_expires_at"] = int(proof_expires_at)
        if proof_scope_hash is not None:
            outcome["proof_scope_hash"] = str(proof_scope_hash)

        if aggregate.decision == RiskDecision.REQUIRE_CONFIRM:
            outcome["override_decision"] = self.cfg.on_confirmed

        return outcome
