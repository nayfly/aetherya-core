from __future__ import annotations

import pytest

from aetherya.output_gate import OutputGate, _compile_term_pattern, _normalize_text


def test_output_gate_normalize_text_compacts_and_strips_accents() -> None:
    assert _normalize_text("  Eres   inútil \n y   tóxico  ") == "eres inutil y toxico"


def test_output_gate_compile_pattern_uses_boundaries() -> None:
    pattern = _compile_term_pattern("idiot")
    assert pattern.search("you are an idiot")
    assert pattern.search("idiot!") is not None
    assert pattern.search("idiotic") is None


def test_output_gate_init_rejects_empty_terms() -> None:
    with pytest.raises(ValueError, match="terms must be non-empty"):
        OutputGate(terms=["   "])


def test_output_gate_evaluate_validation_and_clean_paths() -> None:
    gate = OutputGate()
    with pytest.raises(ValueError, match="must be str"):
        gate.evaluate(123)  # type: ignore[arg-type]

    assert gate.evaluate("   ") is None
    assert gate.evaluate("Thank you for your question.") is None


def test_output_gate_detects_toxic_terms() -> None:
    gate = OutputGate()
    verdict = gate.evaluate("You are an IDIOT, vete a la mierda.")
    assert verdict is not None
    assert verdict.blocked is True
    assert verdict.risk_score == 100
    assert verdict.violated_principle == "OutputSafety"
    assert "output_toxicity" in verdict.tags
    assert "critical_tag_detected" in verdict.tags
    assert "idiot" in verdict.matched_terms
    assert "vete a la mierda" in verdict.matched_terms
    assert verdict.reason.startswith("output toxicity detected:")
