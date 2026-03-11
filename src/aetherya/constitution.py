from __future__ import annotations

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


def _default_model_factory(model_name: str) -> Any:
    from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

    return SentenceTransformer(model_name)


# ---------------------------------------------------------------------------
# Layer 1 — FastKeywordEvaluator
# ---------------------------------------------------------------------------


class FastKeywordEvaluator:
    def __init__(self, principles: list[Principle]) -> None:
        self._principles = principles

    def evaluate(self, text: str) -> dict[str, Any]:
        for p in self._principles:
            for kw in p.keywords:
                kw_lower = kw.lower()
                pos = text.find(kw_lower)
                if pos != -1 and not _has_negation_before(text, pos):
                    return {
                        "allowed": False,
                        "violated_principle": p.name,
                        "risk_score": min(100, max(1, p.risk)),
                        "reason": f"Violates principle: {p.name}",
                        "confidence": 0.9,
                        "ambiguous": False,
                        "tags": [],
                    }

        token_count = len(text.split())
        if token_count < 10:
            return {
                "allowed": True,
                "violated_principle": None,
                "risk_score": 0,
                "reason": "No violations detected",
                "confidence": 0.5,
                "ambiguous": True,
                "tags": [],
            }

        return {
            "allowed": True,
            "violated_principle": None,
            "risk_score": 0,
            "reason": "No violations detected",
            "confidence": 0.8,
            "ambiguous": False,
            "tags": [],
        }


# ---------------------------------------------------------------------------
# Layer 2 — SemanticEvaluator
# ---------------------------------------------------------------------------


class SemanticEvaluator:
    def __init__(
        self,
        principles: list[Principle],
        model_name: str = "all-MiniLM-L6-v2",
        model_factory: Callable[[str], Any] | None = None,
        violation_threshold: float = 0.55,
        gray_zone_threshold: float = 0.35,
    ) -> None:
        self._principles = principles
        self._model_name = model_name
        self._model_factory = model_factory or _default_model_factory
        self._model: Any = None
        self._ref_embeddings: Any = None
        self._ref_principle_indices: list[int] = []
        self._loaded: bool = False
        self._violation_threshold = violation_threshold
        self._gray_zone_threshold = gray_zone_threshold

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
                "risk_score": min(100, max(1, best_p.risk)),
                "reason": f"Semantic violation detected: {best_p.name}",
                "confidence": best_sim,
                "ambiguous": False,
                "tags": [],
            }

        if best_p is not None and best_sim > self._gray_zone_threshold:
            return {
                "allowed": False,
                "violated_principle": best_p.name,
                "risk_score": min(100, max(1, int(best_p.risk * 0.6))),
                "reason": f"Semantic gray zone: {best_p.name}",
                "confidence": best_sim,
                "ambiguous": False,
                "tags": [],
            }

        return {
            "allowed": True,
            "violated_principle": None,
            "risk_score": 0,
            "reason": "No semantic violations detected",
            "confidence": 0.8,
            "ambiguous": False,
            "tags": [],
        }


# ---------------------------------------------------------------------------
# Constitution — orchestrates both layers
# ---------------------------------------------------------------------------


class Constitution:
    def __init__(
        self,
        principles: list[Principle],
        audit: AuditLogger | None = None,
        use_semantic: bool = False,
        semantic_violation_threshold: float = 0.55,
        semantic_gray_zone_threshold: float = 0.35,
    ) -> None:
        self.principles = sorted(principles, key=lambda p: p.priority)
        self.audit = audit
        self._fast_evaluator = FastKeywordEvaluator(self.principles)
        self._semantic_evaluator: SemanticEvaluator | None = (
            SemanticEvaluator(
                self.principles,
                violation_threshold=semantic_violation_threshold,
                gray_zone_threshold=semantic_gray_zone_threshold,
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
        else:
            try:
                sem = self._semantic_evaluator.evaluate(text)
                result = _to_pipeline_result(sem)
            except Exception:
                # Semantic layer unavailable — degrade fast result confidence and continue
                degraded = {
                    **fast,
                    "confidence": max(0.0, float(fast.get("confidence", 0.5)) * 0.8),
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
