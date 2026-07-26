from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from aetherya.actions import ActionRequest
from aetherya.audit import AuditLogger

# ---------------------------------------------------------------------------
# Negation detection helpers
# ---------------------------------------------------------------------------

_NEGATORS_SINGLE: frozenset[str] = frozenset({"not", "no", "never", "without", "avoid", "prevent"})
_NEGATORS_MULTI: tuple[str, ...] = ("how to stop", "how to prevent")
_NEGATION_WINDOW: int = 5


def _has_negation_before(text: str, keyword_start: int) -> bool:
    pre_text = text[:keyword_start].strip()
    window = pre_text.split()[-_NEGATION_WINDOW:]
    if any(tok in _NEGATORS_SINGLE for tok in window):
        return True
    return any(neg in pre_text for neg in _NEGATORS_MULTI)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principle:
    name: str
    description: str
    priority: int = 100
    keywords: list[str] = field(default_factory=list)
    risk: int = 50  # weight if triggered (0-100)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _cosine_sim(a: Any, b: Any) -> float:
    dot = float(np.dot(a, b))
    norm = float(np.linalg.norm(a)) * float(np.linalg.norm(b))
    return dot / (norm + 1e-8)


def _to_pipeline_result(evaluator_result: dict[str, Any]) -> dict[str, Any]:
    """Drop internal-only fields before returning to the pipeline."""
    return {k: v for k, v in evaluator_result.items() if k != "ambiguous"}


# ---------------------------------------------------------------------------
# Lazy sentence-transformer factory (patchable for tests)
# ---------------------------------------------------------------------------


DEFAULT_SEMANTIC_MODEL = "all-MiniLM-L6-v2"

# Ceiling on the risk the semantic layer may contribute. Must stay below the
# lowest `deny_at` across modes (operative: 80) so the learned layer can only
# ever escalate to a human, never deny on its own. See SemanticEvaluator.
DEFAULT_SEMANTIC_MAX_RISK = 60

# Tag attached to every semantic verdict so the audit trace shows when the
# non-deterministic layer influenced a decision. Never a hard-deny tag.
SEMANTIC_ADVISORY_TAG = "semantic_advisory"

_MODEL_CACHE: dict[str, Any] = {}


def _default_model_factory(model_name: str) -> Any:
    if model_name not in _MODEL_CACHE:
        from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

        _MODEL_CACHE[model_name] = SentenceTransformer(model_name)
    return _MODEL_CACHE[model_name]


def is_model_warm(model_name: str = DEFAULT_SEMANTIC_MODEL) -> bool:
    """True when the model is already in the process cache (no cold load needed)."""
    return model_name in _MODEL_CACHE


def warmup_semantic_model(
    model_name: str = DEFAULT_SEMANTIC_MODEL,
    model_factory: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """
    Preload the semantic model into the process cache and run one dummy encode.

    Intended for deployment startup: with use_semantic enabled (the default),
    the first ambiguous input would otherwise trigger the model download/load
    inside the decision path.
    """
    already_cached = model_name in _MODEL_CACHE
    start = time.perf_counter()
    model = (model_factory or _default_model_factory)(model_name)
    model.encode(["aetherya warmup"])
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return {
        "model_name": model_name,
        "already_cached": already_cached,
        "elapsed_ms": round(elapsed_ms, 2),
    }


# ---------------------------------------------------------------------------
# Layer 1 — FastKeywordEvaluator
# ---------------------------------------------------------------------------


class FastKeywordEvaluator:
    def __init__(self, principles: list[Principle]) -> None:
        self._principles = principles

    def evaluate(self, text: str) -> dict[str, Any]:
        first_violation: Principle | None = None
        total_matches: int = 0
        name_match: bool = False
        keyword_found_negated: bool = False

        for p in self._principles:
            for kw in p.keywords:
                kw_lower = kw.lower()
                pos = text.find(kw_lower)
                if pos == -1:
                    continue
                if not _has_negation_before(text, pos):
                    total_matches += 1
                    if kw_lower in p.name.lower():
                        name_match = True
                    if first_violation is None:
                        first_violation = p
                else:
                    keyword_found_negated = True

        if first_violation is not None:
            if name_match:
                confidence = 0.9
            elif total_matches >= 2:
                confidence = 0.85
            else:
                confidence = 0.7
            return {
                "allowed": False,
                "violated_principle": first_violation.name,
                "risk_score": min(100, max(1, first_violation.risk)),
                "reason": f"Violates principle: {first_violation.name}",
                "confidence": confidence,
                "ambiguous": False,
                "tags": [],
            }

        # A keyword was present but negated → definitive allow, no semantic escalation needed.
        if keyword_found_negated:
            return {
                "allowed": True,
                "violated_principle": None,
                "risk_score": 0,
                "reason": "No violations detected",
                "confidence": 0.9,
                "ambiguous": False,
                "tags": [],
            }

        # No keyword evidence either way — the fast layer has nothing to say.
        # Ambiguity is a statement about evidence, not about length: a long,
        # carefully paraphrased input is exactly where keyword matching fails,
        # so it must reach the semantic layer too. Text length only modulates
        # how much confidence the fast layer reports in its own "clean" verdict.
        token_count = len(text.split())
        return {
            "allowed": True,
            "violated_principle": None,
            "risk_score": 0,
            "reason": "No violations detected",
            "confidence": 0.5 if token_count < 10 else 0.8,
            "ambiguous": True,
            "tags": [],
        }


# ---------------------------------------------------------------------------
# Layer 2 — SemanticEvaluator
# ---------------------------------------------------------------------------


class SemanticEvaluator:
    """
    Non-authoritative second layer.

    The semantic layer is the only component in the decision path whose output
    depends on a learned model, so it is deliberately kept unable to decide on
    its own: its risk score is capped at `max_risk` (default 60), which sits
    below the deny threshold of every shipped mode (operative 80, consultive
    90). It can therefore raise a request to `escalate` — never to `deny` or
    `hard_deny` — and it emits no hard-deny tags. Determinism of the *core*
    verdict is preserved: a model change can alter whether a human is asked,
    never whether an action is refused outright.
    """

    def __init__(
        self,
        principles: list[Principle],
        model_name: str = DEFAULT_SEMANTIC_MODEL,
        model_factory: Callable[[str], Any] | None = None,
        violation_threshold: float = 0.55,
        gray_zone_threshold: float = 0.35,
        max_risk: int = DEFAULT_SEMANTIC_MAX_RISK,
        require_warm_model: bool = True,
    ) -> None:
        self._principles = principles
        self._model_name = model_name
        self._model_factory = model_factory or _default_model_factory
        # An injected factory means the caller supplied a ready model, so the
        # warm-model guard does not apply to it.
        self._factory_is_injected = model_factory is not None
        self._model: Any = None
        self._ref_embeddings: Any = None
        self._ref_principle_indices: list[int] = []
        self._loaded: bool = False
        self._violation_threshold = violation_threshold
        self._gray_zone_threshold = gray_zone_threshold
        self._max_risk = max_risk
        self._require_warm_model = require_warm_model

    def can_evaluate(self) -> bool:
        """
        Whether evaluating is free of a cold model load.

        Loading `all-MiniLM-L6-v2` costs ~5 s in a fresh process. That belongs at
        deployment startup (`aetherya warmup`), never inside a decision. When the
        model is not warm the advisory layer declines to run rather than stalling
        the decision path — the same reasoning that makes it non-authoritative in
        the first place: an advisory signal must never be able to hold up a verdict.
        """
        if not self._require_warm_model:
            return True
        return self._loaded or self._factory_is_injected or is_model_warm(self._model_name)

    def _advisory_risk(self, raw_risk: int) -> int:
        """Clamp a principle's risk into the advisory band."""
        return min(self._max_risk, max(1, raw_risk))

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._model = self._model_factory(self._model_name)
        ref_texts: list[str] = []
        for i, p in enumerate(self._principles):
            for t in [p.description, *p.keywords]:
                ref_texts.append(t)
                self._ref_principle_indices.append(i)
        if ref_texts:
            self._ref_embeddings = self._model.encode(ref_texts)
        self._loaded = True

    def evaluate(self, text: str) -> dict[str, Any]:
        self._ensure_loaded()

        if not self._ref_principle_indices or self._ref_embeddings is None:
            return {
                "allowed": True,
                "violated_principle": None,
                "risk_score": 0,
                "reason": "No principles configured",
                "confidence": 0.8,
                "ambiguous": False,
                "tags": [],
                "semantic_score": 0.0,
                "semantic_model": self._model_name,
            }

        query_emb: Any = self._model.encode([text])[0]

        best_sim: float = 0.0
        best_p: Principle | None = None

        for i, p in enumerate(self._principles):
            indices = [j for j, pi in enumerate(self._ref_principle_indices) if pi == i]
            sims = [_cosine_sim(query_emb, self._ref_embeddings[j]) for j in indices]
            max_sim = max(sims)
            if max_sim > best_sim:
                best_sim = max_sim
                best_p = p

        if best_p is not None and best_sim > self._violation_threshold:
            return {
                "allowed": False,
                "violated_principle": best_p.name,
                "risk_score": self._advisory_risk(best_p.risk),
                "reason": f"Semantic violation detected: {best_p.name}",
                "confidence": best_sim,
                "ambiguous": False,
                "tags": [SEMANTIC_ADVISORY_TAG],
                "semantic_score": best_sim,
                "semantic_model": self._model_name,
            }

        if best_p is not None and best_sim > self._gray_zone_threshold:
            return {
                "allowed": False,
                "violated_principle": best_p.name,
                "risk_score": self._advisory_risk(int(best_p.risk * 0.6)),
                "reason": f"Semantic gray zone: {best_p.name}",
                "confidence": best_sim,
                "ambiguous": False,
                "tags": [SEMANTIC_ADVISORY_TAG],
                "semantic_score": best_sim,
                "semantic_model": self._model_name,
            }

        return {
            "allowed": True,
            "violated_principle": None,
            "risk_score": 0,
            "reason": "No semantic violations detected",
            "confidence": 0.8,
            "ambiguous": False,
            "tags": [],
            "semantic_score": best_sim,
            "semantic_model": self._model_name,
        }


# ---------------------------------------------------------------------------
# Constitution — orchestrates both layers
# ---------------------------------------------------------------------------


class Constitution:
    def __init__(
        self,
        principles: list[Principle],
        audit: AuditLogger | None = None,
        use_semantic: bool = True,
        semantic_violation_threshold: float = 0.55,
        semantic_gray_zone_threshold: float = 0.35,
        semantic_max_risk: int = DEFAULT_SEMANTIC_MAX_RISK,
        require_warm_semantic_model: bool = True,
    ) -> None:
        self.principles = sorted(principles, key=lambda p: p.priority)
        self.audit = audit
        self._fast_evaluator = FastKeywordEvaluator(self.principles)
        self._semantic_evaluator: SemanticEvaluator | None = (
            SemanticEvaluator(
                self.principles,
                violation_threshold=semantic_violation_threshold,
                gray_zone_threshold=semantic_gray_zone_threshold,
                max_risk=semantic_max_risk,
                require_warm_model=require_warm_semantic_model,
            )
            if use_semantic
            else None
        )

    def evaluate(
        self,
        action: ActionRequest,
        actor: str = "unknown",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        text = (action.raw_input or "").lower()
        ctx = context or {}

        fast = self._fast_evaluator.evaluate(text)

        if not fast["ambiguous"] or self._semantic_evaluator is None:
            result = _to_pipeline_result(fast)
        elif not self._semantic_evaluator.can_evaluate():
            # Model not warm: run `aetherya warmup` at startup to enable this layer.
            # The decision proceeds on the deterministic result rather than paying a
            # multi-second cold load inside the decision path.
            result = _to_pipeline_result({**fast, "semantic_skipped": "model_not_warm"})
        else:
            try:
                sem = self._semantic_evaluator.evaluate(text)
                result = _to_pipeline_result(sem)
            except Exception:
                # Semantic layer unavailable — degrade fast result confidence and continue
                degraded = {
                    **fast,
                    "confidence": max(0.0, float(fast.get("confidence", 0.5)) * 0.8),
                    "semantic_skipped": "evaluator_error",
                }
                result = _to_pipeline_result(degraded)

        if self.audit:
            self.audit.log(
                actor=actor,
                action=action.raw_input,
                decision=result,
                context={"action": action.__dict__, **ctx},
            )

        return result
