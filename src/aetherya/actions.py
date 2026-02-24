from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ActionRequest:
    """
    A typed representation of a requested action. This is what the Constitution evaluates.
    """

    raw_input: str
    intent: str
    mode_hint: str | None = None  # e.g. "consultive" / "operative"
    tool: str | None = None
    target: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    risk_score: int
    reason: str
    violated_principle: str | None = None
    mode: str | None = None

    def to_dict(self) -> dict:
        """
        Contrato público estable para tests/snapshots.
        OJO: No metas cosas volátiles aquí (timestamps, ids, señales internas, etc.).
        """
        return {
            "allowed": bool(self.allowed),
            "risk_score": int(self.risk_score),
            "reason": str(self.reason),
            "violated_principle": self.violated_principle,
            "mode": str(self.mode),
        }
