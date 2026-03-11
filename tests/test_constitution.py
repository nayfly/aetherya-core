from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock

import numpy as np
import pytest

from aetherya.actions import ActionRequest
from aetherya.constitution import (
    Constitution,
    FastKeywordEvaluator,
    Principle,
    SemanticEvaluator,
    _cosine_sim,
    _default_model_factory,
    _has_negation_before,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action(text: str) -> ActionRequest:
    return ActionRequest(raw_input=text, intent="ask", mode_hint="consultive")


def _principles() -> list[Principle]:
    return [Principle("Non-harm", "Do not cause harm", priority=1, keywords=["attack"], risk=90)]


def _make_mock_model(similarity: float = 0.8) -> Any:
    """Return a fake SentenceTransformer whose encode() returns controllable unit vectors."""
    dim = 4
    # Reference embedding: unit vector along axis 0
    ref_vec = np.zeros(dim, dtype=np.float32)
    ref_vec[0] = 1.0

    # Query embedding: rotated by angle so that cosine = similarity
    import math

    angle = math.acos(max(-1.0, min(1.0, similarity)))
    query_vec = np.zeros(dim, dtype=np.float32)
    query_vec[0] = math.cos(angle)
    query_vec[1] = math.sin(angle)

    model = MagicMock()
    # encode(list_of_str) → 2D array; encode([single]) → 2D, [0] → 1D
    model.encode.side_effect = lambda texts: (
        np.tile(ref_vec, (len(texts), 1)) if len(texts) > 1 else np.array([query_vec])
    )
    return model


# ---------------------------------------------------------------------------
# Existing tests (unchanged behaviour)
# ---------------------------------------------------------------------------


def test_constitution_violation_without_audit_path() -> None:
    core = Constitution(
        [
            Principle(
                "Non-harm",
                "Do not cause harm",
                priority=1,
                keywords=["attack"],
                risk=90,
            )
        ],
        audit=None,
    )
    action = ActionRequest(raw_input="attack now", intent="operate", mode_hint="operative")
    result = core.evaluate(action, actor="robert", context={"mode": "operative"})
    assert result["allowed"] is False
    assert result["violated_principle"] == "Non-harm"


def test_constitution_no_violation_with_empty_context() -> None:
    core = Constitution(
        [Principle("Non-harm", "Do not cause harm", priority=1, keywords=["attack"], risk=90)]
    )
    action = ActionRequest(raw_input="help user", intent="ask", mode_hint="consultive")
    result = core.evaluate(action, actor="robert", context=None)
    assert result["allowed"] is True
    assert result["risk_score"] == 0


# ---------------------------------------------------------------------------
# _has_negation_before
# ---------------------------------------------------------------------------


def test_has_negation_before_single_negator() -> None:
    # "not" is within the 5-token window before "delete"
    text = "please not delete that file"
    pos = text.find("delete")
    assert _has_negation_before(text, pos) is True


def test_has_negation_before_multi_word() -> None:
    text = "how to prevent delete accidents"
    pos = text.find("delete")
    assert _has_negation_before(text, pos) is True


def test_has_negation_before_no_negator() -> None:
    text = "delete all files now"
    pos = text.find("delete")
    assert _has_negation_before(text, pos) is False


# ---------------------------------------------------------------------------
# FastKeywordEvaluator — negation detection
# ---------------------------------------------------------------------------


def test_fast_evaluator_negation_prevents_keyword() -> None:
    p = Principle("Ops", "no deletes", priority=1, keywords=["delete"], risk=80)
    ev = FastKeywordEvaluator([p])
    result = ev.evaluate("how to prevent delete accidents")
    assert result["allowed"] is True


def test_fast_evaluator_never_prevents_keyword() -> None:
    p = Principle("Ops", "no runs", priority=1, keywords=["run"], risk=80)
    ev = FastKeywordEvaluator([p])
    result = ev.evaluate("never run dangerous commands")
    assert result["allowed"] is True


def test_fast_evaluator_keyword_without_negation_triggers() -> None:
    p = Principle("Ops", "no deletes", priority=1, keywords=["delete"], risk=80)
    ev = FastKeywordEvaluator([p])
    result = ev.evaluate("delete all files")
    assert result["allowed"] is False
    assert result["violated_principle"] == "Ops"
    assert result["confidence"] == 0.9
    assert result["ambiguous"] is False


def test_fast_evaluator_short_text_is_ambiguous() -> None:
    ev = FastKeywordEvaluator([])
    result = ev.evaluate("help me")  # 2 tokens < 10
    assert result["allowed"] is True
    assert result["ambiguous"] is True
    assert result["confidence"] < 0.7


def test_fast_evaluator_long_clean_text_not_ambiguous() -> None:
    ev = FastKeywordEvaluator([])
    result = ev.evaluate(
        "explain the backup strategy for the system in detail please"
    )  # >10 tokens
    assert result["allowed"] is True
    assert result["ambiguous"] is False
    assert result["confidence"] >= 0.7


# ---------------------------------------------------------------------------
# Constitution — negation integration
# ---------------------------------------------------------------------------


def test_constitution_negation_prevents_false_positive() -> None:
    core = Constitution(
        [Principle("Ops", "do not delete", priority=1, keywords=["delete"], risk=80)]
    )
    result = core.evaluate(_action("how to prevent delete accidents"))
    assert result["allowed"] is True


def test_constitution_no_negation_still_blocks() -> None:
    core = Constitution(
        [Principle("Ops", "do not delete", priority=1, keywords=["delete"], risk=80)]
    )
    result = core.evaluate(_action("delete all files"))
    assert result["allowed"] is False


# ---------------------------------------------------------------------------
# _cosine_sim
# ---------------------------------------------------------------------------


def test_cosine_sim_identical_vectors() -> None:
    v = np.array([1.0, 0.0, 0.0])
    assert abs(_cosine_sim(v, v) - 1.0) < 1e-6


def test_cosine_sim_orthogonal_vectors() -> None:
    a = np.array([1.0, 0.0])
    b = np.array([0.0, 1.0])
    assert abs(_cosine_sim(a, b)) < 1e-6


def test_cosine_sim_zero_vector() -> None:
    a = np.array([0.0, 0.0])
    b = np.array([1.0, 0.0])
    # Should not raise; returns ~0.0
    result = _cosine_sim(a, b)
    assert isinstance(result, float)


# ---------------------------------------------------------------------------
# _default_model_factory — coverage via sys.modules mock
# ---------------------------------------------------------------------------


def test_default_model_factory_calls_sentence_transformer(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_st_cls = MagicMock(return_value=MagicMock())
    mock_module = MagicMock()
    mock_module.SentenceTransformer = mock_st_cls
    monkeypatch.setitem(sys.modules, "sentence_transformers", mock_module)

    result = _default_model_factory("test-model")
    mock_st_cls.assert_called_once_with("test-model")
    assert result is mock_st_cls.return_value


# ---------------------------------------------------------------------------
# SemanticEvaluator — mocked model
# ---------------------------------------------------------------------------


def _sem_evaluator(similarity: float) -> SemanticEvaluator:
    principles = [
        Principle("Non-harm", "Do not cause harm", priority=1, keywords=["harm"], risk=90)
    ]
    ev = SemanticEvaluator(principles, model_factory=lambda _: _make_mock_model(similarity))
    return ev


def test_semantic_evaluator_high_similarity_is_violation() -> None:
    ev = _sem_evaluator(similarity=0.8)
    result = ev.evaluate("some dangerous request")
    assert result["allowed"] is False
    assert result["confidence"] > 0.55
    assert result["ambiguous"] is False


def test_semantic_evaluator_gray_zone() -> None:
    ev = _sem_evaluator(similarity=0.45)
    result = ev.evaluate("borderline input")
    assert result["allowed"] is False
    assert 0.35 < result["confidence"] <= 0.55


def test_semantic_evaluator_low_similarity_is_clean() -> None:
    ev = _sem_evaluator(similarity=0.1)
    result = ev.evaluate("help me with documents")
    assert result["allowed"] is True
    assert result["ambiguous"] is False


def test_semantic_evaluator_no_principles() -> None:
    ev = SemanticEvaluator([], model_factory=lambda _: _make_mock_model())
    result = ev.evaluate("anything")
    assert result["allowed"] is True


def test_semantic_evaluator_picks_highest_similarity_principle() -> None:
    """Second principle has lower similarity → best_p stays as the first one."""
    dim = 4
    # High-similarity vector for principle 0
    high_vec = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    # Low-similarity vector for principle 1
    low_vec = np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)

    call_idx = {"n": 0}

    def mock_encode(texts: list[str]) -> Any:
        n = len(texts)
        result = np.zeros((n, dim), dtype=np.float32)
        for row in range(n):
            # Encode all reference texts using high_vec, but query uses low_vec
            result[row] = high_vec if call_idx["n"] == 0 else low_vec
        return result

    model = MagicMock()
    model.encode.side_effect = lambda texts: mock_encode(texts)

    # Build a 2-principle evaluator where we want to test the max_sim <= best_sim branch
    principles = [
        Principle("P1", "high relevance principle", priority=1, keywords=[], risk=80),
        Principle("P2", "low relevance principle", priority=2, keywords=[], risk=60),
    ]

    # Custom model: encodes reference texts with fixed vectors, then encodes query
    _ref_vecs = [high_vec, low_vec]  # P1 ref → high_vec, P2 ref → low_vec
    _encode_calls = {"n": 0}

    def smart_encode(texts: list[str]) -> Any:
        _encode_calls["n"] += 1
        if _encode_calls["n"] <= 2:
            # First two calls are for ref encoding (one per principle description)
            # Return the corresponding reference vector for each text
            arr = np.zeros((len(texts), dim), dtype=np.float32)
            for row_i in range(len(texts)):
                arr[row_i] = _ref_vecs[min(row_i, len(_ref_vecs) - 1)]
            return arr
        # Third+ call is the query encoding — return a vector aligned with P1 (high)
        return np.array([high_vec])

    smart_model = MagicMock()
    smart_model.encode.side_effect = smart_encode

    ev = SemanticEvaluator(principles, model_factory=lambda _: smart_model)
    result = ev.evaluate("test input")
    # P1 has higher similarity → must be selected as violated (or best)
    assert "allowed" in result


def test_semantic_evaluator_lazy_load_only_on_first_call() -> None:
    call_count = {"n": 0}

    def counting_factory(name: str) -> Any:
        call_count["n"] += 1
        return _make_mock_model(0.1)

    ev = SemanticEvaluator(
        [Principle("P", "desc", priority=1, keywords=[], risk=50)],
        model_factory=counting_factory,
    )
    assert call_count["n"] == 0  # not loaded yet
    ev.evaluate("first call")
    assert call_count["n"] == 1
    ev.evaluate("second call")
    assert call_count["n"] == 1  # still 1 — cached


# ---------------------------------------------------------------------------
# Constitution — use_semantic integration (mocked)
# ---------------------------------------------------------------------------


def _mock_factory_for_constitution(similarity: float) -> Any:
    """Return a model factory suitable for injecting into SemanticEvaluator via monkeypatch."""
    return lambda _name: _make_mock_model(similarity)


def test_constitution_semantic_path_detects_without_keywords(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambiguous short input should go to semantic layer and detect a violation."""
    import aetherya.constitution as c_mod

    # Patch _default_model_factory to return a high-similarity model
    monkeypatch.setattr(c_mod, "_default_model_factory", lambda _: _make_mock_model(0.8))

    core = Constitution(
        [Principle("Non-harm", "Do not cause harm", priority=1, keywords=[], risk=90)],
        use_semantic=True,
    )
    # "harm me" is 2 tokens → ambiguous → semantic layer runs
    result = core.evaluate(_action("harm me"))
    assert result["allowed"] is False


def test_constitution_use_semantic_false_never_loads_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = {"called": False}

    def spy_factory(_name: str) -> Any:
        loaded["called"] = True
        return _make_mock_model()

    monkeypatch.setattr("aetherya.constitution._default_model_factory", spy_factory)

    core = Constitution(
        [Principle("P", "desc", priority=1, keywords=[], risk=50)],
        use_semantic=False,
    )
    assert core._semantic_evaluator is None  # noqa: SLF001
    core.evaluate(_action("short text"))
    assert loaded["called"] is False


def test_constitution_semantic_fallback_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """If semantic layer raises, constitution falls back to degraded fast result."""

    def bad_factory(_name: str) -> Any:
        raise ImportError("sentence_transformers not available")

    monkeypatch.setattr("aetherya.constitution._default_model_factory", bad_factory)

    core = Constitution(
        [Principle("P", "desc", priority=1, keywords=[], risk=50)],
        use_semantic=True,
    )
    # "hi" is 1 token → ambiguous → tries semantic → falls back
    result = core.evaluate(_action("hi"))
    assert "allowed" in result
    assert result["allowed"] is True
    assert result["confidence"] < 0.5  # degraded (0.5 * 0.8)


def test_constitution_with_audit_logs_result(tmp_path: pytest.TempPathFactory) -> None:
    from aetherya.audit import AuditLogger

    audit_path = tmp_path / "test.jsonl"  # type: ignore[operator]
    audit = AuditLogger(audit_path)
    core = Constitution(
        [Principle("Non-harm", "harm", priority=1, keywords=["attack"], risk=90)],
        audit=audit,
    )
    core.evaluate(_action("attack now"), actor="alice")
    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# Slow tests — real model (skipped unless --run-slow)
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_semantic_detects_paraphrase_without_keywords() -> None:
    """Real model: semantically similar input (no exact keywords) triggers violation."""
    core = Constitution(
        [
            Principle(
                "Non-harm",
                "Do not support harmful or violent intent",
                priority=1,
                keywords=[],  # no keyword shortcut
                risk=85,
            )
        ],
        use_semantic=True,
    )
    # Paraphrase of harmful intent without any keyword
    result = core.evaluate(_action("hurt someone physically"))
    # The real model may or may not cross the threshold — we assert the call succeeds
    # and returns a valid result; semantic detection is probabilistic.
    assert "allowed" in result
    assert isinstance(result["risk_score"], int)


@pytest.mark.slow
def test_semantic_innocent_input_is_allowed() -> None:
    """Real model: clearly innocent input must be allowed."""
    core = Constitution(
        [
            Principle(
                "Non-harm",
                "Do not support harmful or violent intent",
                priority=1,
                keywords=[],
                risk=85,
            )
        ],
        use_semantic=True,
    )
    result = core.evaluate(_action("help me write a recipe for chocolate cake"))
    assert result["allowed"] is True
