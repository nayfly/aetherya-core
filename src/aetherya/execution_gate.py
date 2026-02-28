from __future__ import annotations

from typing import TypedDict

from aetherya.actions import ActionRequest
from aetherya.config import ExecutionGateConfig


class ExecutionGateResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


class ExecutionGate:
    def __init__(self, cfg: ExecutionGateConfig) -> None:
        self.cfg = cfg

    def evaluate(self, action: ActionRequest) -> ExecutionGateResult | None:
        if not self.cfg.enabled:
            return None

        if action.intent != "operate":
            return None

        tool = (action.tool or "").strip()
        target = (action.target or "").strip()
        params = action.parameters

        if not tool:
            return {
                "risk_score": 55,
                "confidence": 0.9,
                "reason": "missing tool for operative request",
                "tags": ["execution_contract_missing", "missing_tool"],
            }

        if self.cfg.allowed_tools and tool not in self.cfg.allowed_tools:
            return {
                "risk_score": 95,
                "confidence": 0.95,
                "reason": "tool not allowed by execution gate",
                "tags": ["execution_contract_violation", "tool_not_allowed"],
            }

        if self.cfg.require_target_for_operate and not target:
            return {
                "risk_score": 65,
                "confidence": 0.9,
                "reason": "missing target for operative request",
                "tags": ["execution_contract_missing", "missing_target"],
            }

        required_params = self.cfg.required_parameters.get(tool, [])
        missing_required = [p for p in required_params if p not in params]
        if missing_required:
            return {
                "risk_score": 75,
                "confidence": 0.9,
                "reason": "missing required parameters for tool",
                "tags": ["execution_contract_violation", "missing_required_parameter"],
            }

        allowed_params = self.cfg.allowed_parameters.get(tool, [])
        if allowed_params:
            extra = [p for p in params if p not in allowed_params and not p.startswith("confirm_")]
            if extra:
                return {
                    "risk_score": 85,
                    "confidence": 0.9,
                    "reason": "unexpected parameters for tool",
                    "tags": ["execution_contract_violation", "parameter_not_allowed"],
                }

        return None
