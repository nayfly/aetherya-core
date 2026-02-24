from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aetherya.actions import ActionRequest
from aetherya.audit import AuditLogger


@dataclass(frozen=True)
class Principle:
    name: str
    description: str
    priority: int = 100
    keywords: list[str] = field(default_factory=list)
    risk: int = 50  # cuánto “pesa” si salta (0-100)


class Constitution:
    def __init__(self, principles: list[Principle], audit: AuditLogger | None = None) -> None:
        self.principles = sorted(principles, key=lambda p: p.priority)
        self.audit = audit

    def evaluate(
        self,
        action: ActionRequest,
        actor: str = "unknown",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Returns a normalized result consumed by PolicyEngine.
        """
        text = (action.raw_input or "").lower()
        ctx = context or {}

        for p in self.principles:
            if any(k.lower() in text for k in p.keywords):
                result = {
                    "allowed": False,
                    "violated_principle": p.name,
                    "risk_score": min(100, max(1, p.risk)),
                    "reason": f"Violates principle: {p.name}",
                }
                if self.audit:
                    self.audit.log(
                        actor=actor,
                        action=action.raw_input,
                        decision=result,
                        context={"action": action.__dict__, **ctx},
                    )
                return result

        result = {"allowed": True, "risk_score": 0, "reason": "No violations detected"}
        if self.audit:
            self.audit.log(
                actor=actor,
                action=action.raw_input,
                decision=result,
                context={"action": action.__dict__, **ctx},
            )
        return result
