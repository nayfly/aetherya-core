from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

_ALLOWED_MODES = frozenset({"consultive", "operative"})
_ALLOWED_DECISION_STATES = frozenset({"allow", "log_only", "require_confirm", "deny", "hard_deny"})


def _normalize_payload(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return str(value)
    if isinstance(value, dict):
        return {str(k): _normalize_payload(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalize_payload(v) for v in value]
    if isinstance(value, set):
        normalized = [_normalize_payload(v) for v in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
    return f"<{type(value).__module__}.{type(value).__qualname__}>"


@dataclass(frozen=True)
class PolicyDecisionRequest:
    actor: str
    mode: str
    raw_input: str
    trace_id: str
    action: dict[str, Any] = field(default_factory=dict)
    baseline: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        actor = self.actor.strip().lower() if isinstance(self.actor, str) else ""
        if not actor:
            raise ValueError("actor must be non-empty str")
        mode = self.mode.strip().lower() if isinstance(self.mode, str) else ""
        if mode not in _ALLOWED_MODES:
            raise ValueError("mode must be one of: consultive, operative")
        if not isinstance(self.raw_input, str) or not self.raw_input.strip():
            raise ValueError("raw_input must be non-empty str")
        if not isinstance(self.trace_id, str) or not self.trace_id.strip():
            raise ValueError("trace_id must be non-empty str")
        if not isinstance(self.action, dict):
            raise ValueError("action must be dict")
        if not isinstance(self.baseline, dict):
            raise ValueError("baseline must be dict")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be dict")

    def normalized(self) -> dict[str, Any]:
        self.validate()
        return {
            "actor": self.actor.strip().lower(),
            "mode": self.mode.strip().lower(),
            "raw_input": self.raw_input.strip(),
            "trace_id": self.trace_id.strip(),
            "action": _normalize_payload(self.action),
            "baseline": _normalize_payload(self.baseline),
            "metadata": _normalize_payload(self.metadata),
        }


@dataclass(frozen=True)
class PolicySignalCandidate:
    source: str
    score: int
    confidence: float = 1.0
    reason: str = ""
    tags: list[str] = field(default_factory=list)
    violated_principle: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("source must be non-empty str")
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise ValueError("score must be int")
        if not isinstance(self.confidence, int | float) or math.isnan(float(self.confidence)):
            raise ValueError("confidence must be numeric")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if not isinstance(self.reason, str):
            raise ValueError("reason must be str")
        if not isinstance(self.tags, list) or any(not isinstance(tag, str) for tag in self.tags):
            raise ValueError("tags must be list[str]")
        if self.violated_principle is not None and (
            not isinstance(self.violated_principle, str) or not self.violated_principle.strip()
        ):
            raise ValueError("violated_principle must be None or non-empty str")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be dict")


@dataclass(frozen=True)
class PolicyDecisionCandidate:
    state: str
    confidence: float
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        state = self.state.strip().lower() if isinstance(self.state, str) else ""
        if state not in _ALLOWED_DECISION_STATES:
            raise ValueError(
                "state must be one of: allow, log_only, require_confirm, deny, hard_deny"
            )
        if not isinstance(self.confidence, int | float) or math.isnan(float(self.confidence)):
            raise ValueError("confidence must be numeric")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be non-empty str")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be dict")


@dataclass(frozen=True)
class PolicyDecisionResponse:
    request_id: str
    adapter: str
    signals: list[PolicySignalCandidate] = field(default_factory=list)
    decision_candidates: list[PolicyDecisionCandidate] = field(default_factory=list)
    dry_run: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ValueError("request_id must be non-empty str")
        if not isinstance(self.adapter, str) or not self.adapter.strip():
            raise ValueError("adapter must be non-empty str")
        if not isinstance(self.signals, list):
            raise ValueError("signals must be list")
        for signal in self.signals:
            if not isinstance(signal, PolicySignalCandidate):
                raise ValueError("signals must contain PolicySignalCandidate items")
            signal.validate()
        if not isinstance(self.decision_candidates, list):
            raise ValueError("decision_candidates must be list")
        for candidate in self.decision_candidates:
            if not isinstance(candidate, PolicyDecisionCandidate):
                raise ValueError("decision_candidates must contain PolicyDecisionCandidate items")
            candidate.validate()
        if not isinstance(self.dry_run, bool):
            raise ValueError("dry_run must be bool")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be dict")


@runtime_checkable
class PolicyDecisionAdapter(Protocol):
    adapter_name: str

    def suggest(self, request: PolicyDecisionRequest) -> PolicyDecisionResponse: ...


def ensure_policy_decision_adapter(adapter: Any) -> PolicyDecisionAdapter:
    if not isinstance(adapter, PolicyDecisionAdapter):
        raise ValueError("adapter must implement PolicyDecisionAdapter")
    return adapter


def _request_hash(seed: str, request: PolicyDecisionRequest) -> str:
    payload = {"seed": seed, **request.normalized()}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


class DryRunPolicyDecisionAdapter:
    adapter_name = "dry_run_policy_adapter"

    def __init__(self, seed: str = "aetherya:policy-adapter:v1") -> None:
        self.seed = seed

    def suggest(self, request: PolicyDecisionRequest) -> PolicyDecisionResponse:
        request.validate()
        req_hash = _request_hash(self.seed, request)
        text = request.raw_input.strip().lower()

        signal: PolicySignalCandidate | None = None
        if _contains_any(
            text,
            (
                "ignore previous instructions",
                "system prompt",
                "jailbreak",
                "developer mode",
            ),
        ):
            signal = PolicySignalCandidate(
                source="external_context_adapter",
                score=35,
                confidence=0.65,
                reason="dry_run: prompt-injection pattern similarity",
                tags=["dry_run_external_signal", "jailbreak_likelihood"],
                violated_principle="PromptSafety",
                metadata={"strategy": "keyword_similarity"},
            )
        elif _contains_any(text, ("rm -rf", "mkfs", "drop table", "delete all")):
            signal = PolicySignalCandidate(
                source="external_context_adapter",
                score=20,
                confidence=0.55,
                reason="dry_run: destructive-intent retrieval match",
                tags=["dry_run_external_signal", "destructive_intent_similarity"],
                violated_principle="ExecutionSafety",
                metadata={"strategy": "keyword_similarity"},
            )
        elif _contains_any(text, ("sudo", "privileged", "root access")):
            signal = PolicySignalCandidate(
                source="external_context_adapter",
                score=10,
                confidence=0.5,
                reason="dry_run: privileged-operation context hint",
                tags=["dry_run_external_signal", "privileged_context_hint"],
                violated_principle="ProceduralSafety",
                metadata={"strategy": "keyword_similarity"},
            )

        signals = [signal] if signal else []
        response = PolicyDecisionResponse(
            request_id=f"policy-adapter:{req_hash[:24]}",
            adapter=self.adapter_name,
            signals=signals,
            decision_candidates=[],
            dry_run=True,
            metadata={"request_hash": req_hash, "seed": self.seed},
        )
        response.validate()
        return response
