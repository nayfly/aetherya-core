from __future__ import annotations

from typing import TypedDict

from aetherya.actions import ActionRequest
from aetherya.config import CapabilityMatrixConfig


class CapabilityGateResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


class CapabilityGate:
    def __init__(self, cfg: CapabilityMatrixConfig) -> None:
        self.cfg = cfg

    def _actor_capabilities(self, actor: str) -> tuple[set[str], set[str], list[str]]:
        actor_id = actor.strip().lower()
        actor_cfg = self.cfg.actors.get(actor_id)
        if actor_cfg is None:
            return set(), set(), []

        tools = {t.strip().lower() for t in actor_cfg.tools}
        operations = {op.strip().lower() for op in actor_cfg.operations}
        missing_roles: list[str] = []

        for role in actor_cfg.roles:
            role_cfg = self.cfg.roles.get(role)
            if role_cfg is None:
                missing_roles.append(role)
                continue
            tools.update(t.strip().lower() for t in role_cfg.tools)
            operations.update(op.strip().lower() for op in role_cfg.operations)

        return tools, operations, missing_roles

    def evaluate(self, *, actor: str, action: ActionRequest) -> CapabilityGateResult | None:
        if not self.cfg.enabled:
            return None

        if action.intent != "operate":
            return None

        tools, operations, missing_roles = self._actor_capabilities(actor)
        actor_known = actor.strip().lower() in self.cfg.actors

        if not actor_known and not self.cfg.default_allow:
            return {
                "risk_score": 90,
                "confidence": 0.95,
                "reason": "unknown actor in capability matrix",
                "tags": ["capability_violation", "capability_unknown_actor"],
            }

        if actor_known and missing_roles:
            return {
                "risk_score": 92,
                "confidence": 0.95,
                "reason": "actor has unknown role reference in capability matrix",
                "tags": ["capability_violation", "capability_unknown_role"],
            }

        tool = (action.tool or "").strip().lower()
        if actor_known and tool and tool not in tools:
            return {
                "risk_score": 95,
                "confidence": 0.95,
                "reason": "actor not allowed to use requested tool",
                "tags": ["capability_violation", "capability_tool_denied"],
            }

        op_raw = action.parameters.get("operation")
        operation = str(op_raw).strip().lower() if op_raw is not None else ""
        if actor_known and operation and operation not in operations:
            return {
                "risk_score": 90,
                "confidence": 0.9,
                "reason": "actor not allowed for requested operation",
                "tags": ["capability_violation", "capability_operation_denied"],
            }

        return None
