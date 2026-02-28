from __future__ import annotations

from typing import Any, TypedDict

from aetherya.config import ProceduralGuardConfig


class GuardResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


def _validate_guard_result(result: dict[str, Any]) -> GuardResult:
    if not isinstance(result, dict):
        raise ValueError("GuardResult must be dict")

    risk_score = result.get("risk_score")
    if not isinstance(risk_score, int):
        raise ValueError("risk_score must be int")

    confidence = result.get("confidence")
    if not isinstance(confidence, int | float):
        raise ValueError("confidence must be float")

    tags = result.get("tags")
    if not isinstance(tags, list):
        raise ValueError("tags must be list")
    if any(not isinstance(t, str) for t in tags):
        raise ValueError("tags must be list[str]")

    reason = result.get("reason")
    if not isinstance(reason, str):
        raise ValueError("reason must be str")

    # Devolvemos un GuardResult “tipado”, no el dict original genérico
    return {
        "risk_score": risk_score,
        "confidence": float(confidence),
        "reason": reason,
        "tags": tags,
    }


class ProceduralGuard:
    def __init__(self, cfg: ProceduralGuardConfig) -> None:
        self.cfg = cfg

    def evaluate(self, text: str) -> GuardResult | None:
        t = text.lower().strip()

        for critical_tag in getattr(self.cfg, "critical_tags", []):
            if critical_tag.lower() in t:
                return _validate_guard_result(
                    {
                        "risk_score": 100,
                        "reason": "destructive system command",
                        "tags": ["critical_tag_detected", "data_destruction"],
                        "confidence": 1.0,
                    }
                )

        # Ejemplo privileged ops
        for op in getattr(self.cfg, "privileged_ops", []):
            if "sudo" in t and op in t:
                return _validate_guard_result(
                    {
                        "risk_score": 45,
                        "reason": "privileged package removal",
                        "tags": ["system_change"],
                        "confidence": 0.65,
                    }
                )

        return None
