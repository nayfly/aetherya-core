import pytest

from aetherya.procedural_guard import _validate_guard_result


def test_validate_guard_result_rejects_non_int_risk_score() -> None:
    with pytest.raises(ValueError):
        _validate_guard_result(
            {"risk_score": "95", "confidence": 0.5, "reason": "x", "tags": ["a"]}
        )


def test_validate_guard_result_rejects_non_numeric_confidence() -> None:
    with pytest.raises(ValueError):
        _validate_guard_result(
            {"risk_score": 10, "confidence": "nope", "reason": "x", "tags": ["a"]}
        )


def test_validate_guard_result_rejects_tags_not_list_str() -> None:
    with pytest.raises(ValueError):
        _validate_guard_result(
            {"risk_score": 10, "confidence": 0.5, "reason": "x", "tags": ["ok", 1]}
        )


def test_validate_guard_result_rejects_tags_not_list() -> None:
    with pytest.raises(ValueError, match="tags must be list"):
        _validate_guard_result(
            {
                "risk_score": 10,
                "confidence": 0.5,
                "tags": "nope",
                "reason": "ok",
            }
        )
