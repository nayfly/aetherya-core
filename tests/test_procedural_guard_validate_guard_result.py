import pytest

from aetherya.procedural_guard import _validate_guard_result


def test_validate_guard_result_rejects_non_dict() -> None:
    with pytest.raises(ValueError):
        _validate_guard_result("nope")  # type: ignore[arg-type]


def test_validate_guard_result_rejects_bad_confidence_type() -> None:
    with pytest.raises(ValueError):
        _validate_guard_result({"risk_score": 1, "confidence": "nope", "reason": "x", "tags": []})


def test_validate_guard_result_rejects_bad_reason_type() -> None:
    with pytest.raises(ValueError):
        _validate_guard_result({"risk_score": 1, "confidence": 0.5, "reason": 123, "tags": []})
