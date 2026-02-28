from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

POLICY_ABI_VERSION: Final[str] = "v1"
_VALID_INTENTS: Final[frozenset[str]] = frozenset({"ask", "operate"})
_VALID_DECISION_STATES: Final[frozenset[str]] = frozenset(
    {"allow", "log_only", "escalate", "deny", "hard_deny"}
)


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

    def validate(self) -> None:
        if not isinstance(self.raw_input, str):
            raise ValueError("raw_input must be str")

        if not isinstance(self.intent, str) or self.intent not in _VALID_INTENTS:
            raise ValueError("intent must be one of: ask, operate")

        if self.mode_hint is not None and not isinstance(self.mode_hint, str):
            raise ValueError("mode_hint must be str | None")

        if self.tool is not None and not isinstance(self.tool, str):
            raise ValueError("tool must be str | None")

        if self.target is not None and not isinstance(self.target, str):
            raise ValueError("target must be str | None")

        if not isinstance(self.parameters, dict):
            raise ValueError("parameters must be dict[str, Any]")

        if any(not isinstance(k, str) for k in self.parameters):
            raise ValueError("parameters keys must be str")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    risk_score: int
    reason: str
    violated_principle: str | None = None
    mode: str | None = None
    state: str = "allow"
    abi_version: str = POLICY_ABI_VERSION

    def validate(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError("allowed must be bool")

        if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, int):
            raise ValueError("risk_score must be int")

        if not isinstance(self.reason, str):
            raise ValueError("reason must be str")

        if self.violated_principle is not None and not isinstance(self.violated_principle, str):
            raise ValueError("violated_principle must be str | None")

        if self.mode is not None and not isinstance(self.mode, str):
            raise ValueError("mode must be str | None")

        if not isinstance(self.state, str) or self.state not in _VALID_DECISION_STATES:
            raise ValueError("state must be a valid decision state")

        if self.abi_version != POLICY_ABI_VERSION:
            raise ValueError(f"abi_version must be {POLICY_ABI_VERSION}")

    def to_dict(self) -> dict[str, Any]:
        """
        Contrato público estable para tests/snapshots.
        OJO: No metas cosas volátiles aquí (timestamps, ids, señales internas, etc.).
        """
        self.validate()
        return {
            "allowed": bool(self.allowed),
            "risk_score": int(self.risk_score),
            "reason": str(self.reason),
            "violated_principle": self.violated_principle,
            "mode": self.mode,
            "state": self.state,
            "abi_version": self.abi_version,
        }


def validate_actor(actor: Any) -> str:
    if not isinstance(actor, str):
        raise ValueError("actor must be str")

    actor_clean = actor.strip()
    if not actor_clean:
        raise ValueError("actor must be non-empty str")

    return actor_clean


def validate_action_request(action: Any) -> ActionRequest:
    if not isinstance(action, ActionRequest):
        raise ValueError("action_request must be ActionRequest")

    action.validate()
    return action
