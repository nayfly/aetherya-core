from __future__ import annotations

from typing import TypedDict

from aetherya.config import ProceduralGuardConfig


class GuardResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


class ProceduralGuard:
    def __init__(self, cfg: ProceduralGuardConfig) -> None:
        self.cfg = cfg

    def evaluate(self, text: str) -> GuardResult | None:
        t = text.lower().strip()

        # Ejemplo destructivo
        if "rm -rf /" in t or "mkfs" in t:
            return {
                "risk_score": 95,  # o 100 si quieres “hard”
                "reason": "destructive system command",
                "tags": ["data_destruction"],
                "confidence": 0.95,
            }

        # Ejemplo privileged ops
        for op in self.cfg.privileged_ops:
            if "sudo" in t and op in t:
                return {
                    "risk_score": 45,
                    "reason": "privileged package removal",
                    "tags": ["system_change"],
                    "confidence": 0.65,
                }

        return None
