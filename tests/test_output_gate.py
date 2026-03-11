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


# --- PII detection tests ---


def _pii(text: str) -> OutputGateVerdict | None:  # noqa: F821
    from aetherya.output_gate import OutputGate as _G

    return _G().evaluate(text)


def _assert_pii(verdict: OutputGateVerdict | None) -> None:  # noqa: F821
    assert verdict is not None
    assert verdict.blocked is True
    assert verdict.risk_score == 85
    assert verdict.confidence == 0.9
    assert "pii_detected" in verdict.tags
    assert "output_sensitive_data" in verdict.tags
    assert verdict.violated_principle == "DataPrivacy"


def test_output_gate_detects_email() -> None:
    _assert_pii(_pii("Contact us at user.name+tag@example.co.uk for details."))


def test_output_gate_detects_credit_card_plain() -> None:
    _assert_pii(_pii("Your card number is 4111111111111111."))


def test_output_gate_detects_credit_card_formatted() -> None:
    _assert_pii(_pii("Charge card 4111-1111-1111-1111 for the amount."))


def test_output_gate_detects_openai_api_key() -> None:
    _assert_pii(_pii("Use key sk-abcdefghijklmnopqrstuvwxyz123456 to authenticate."))


def test_output_gate_detects_github_token() -> None:
    _assert_pii(_pii("Token: ghp_" + "A" * 36))


def test_output_gate_detects_slack_token() -> None:
    _assert_pii(_pii("Slack token xoxb-abc123-def456-ghijklmn"))


def test_output_gate_detects_bearer_token() -> None:
    _assert_pii(_pii("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"))


def test_output_gate_detects_dni() -> None:
    _assert_pii(_pii("Su DNI es 12345678Z, por favor confírmelo."))


def test_output_gate_detects_nie() -> None:
    _assert_pii(_pii("El NIE del solicitante es X1234567A."))


def test_output_gate_detects_iban() -> None:
    _assert_pii(_pii("Transfiera a ES9121000418450200051332."))


def test_output_gate_clean_text_returns_none() -> None:
    gate = OutputGate()
    assert gate.evaluate("The answer is 42 and everything is fine.") is None
