from __future__ import annotations

import pytest

from aetherya.actions import (
    POLICY_ABI_VERSION,
    ActionRequest,
    Decision,
    validate_action_request,
    validate_actor,
)


def test_action_request_validate_happy_path() -> None:
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        mode_hint="operative",
        tool="shell",
        target="local",
        parameters={"command": "ls"},
    )
    action.validate()


def test_action_request_validate_rejects_bad_intent() -> None:
    action = ActionRequest(raw_input="x", intent="unknown")
    with pytest.raises(ValueError, match="intent must be one of"):
        action.validate()


def test_action_request_validate_rejects_non_str_raw_input() -> None:
    action = ActionRequest(raw_input=123, intent="ask")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="raw_input must be str"):
        action.validate()


def test_action_request_validate_rejects_non_str_mode_hint() -> None:
    action = ActionRequest(raw_input="x", intent="ask", mode_hint=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mode_hint must be str"):
        action.validate()


def test_action_request_validate_rejects_non_str_tool() -> None:
    action = ActionRequest(raw_input="x", intent="ask", tool=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="tool must be str"):
        action.validate()


def test_action_request_validate_rejects_non_str_target() -> None:
    action = ActionRequest(raw_input="x", intent="ask", target=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="target must be str"):
        action.validate()


def test_action_request_validate_rejects_non_dict_params() -> None:
    action = ActionRequest(raw_input="x", intent="ask", parameters="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="parameters must be dict"):
        action.validate()


def test_action_request_validate_rejects_non_str_param_key() -> None:
    action = ActionRequest(
        raw_input="x",
        intent="ask",
        parameters={1: "bad"},  # type: ignore[dict-item]
    )
    with pytest.raises(ValueError, match="parameters keys must be str"):
        action.validate()


def test_decision_validate_rejects_bad_state() -> None:
    d = Decision(allowed=True, risk_score=0, reason="ok", state="bad")
    with pytest.raises(ValueError, match="state must be a valid decision state"):
        d.validate()


def test_decision_validate_rejects_non_bool_allowed() -> None:
    d = Decision(allowed=1, risk_score=0, reason="ok")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="allowed must be bool"):
        d.validate()


def test_decision_validate_rejects_non_int_risk_score() -> None:
    d = Decision(allowed=True, risk_score="1", reason="ok")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="risk_score must be int"):
        d.validate()


def test_decision_validate_rejects_bool_risk_score() -> None:
    d = Decision(allowed=True, risk_score=True, reason="ok")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="risk_score must be int"):
        d.validate()


def test_decision_validate_rejects_non_str_reason() -> None:
    d = Decision(allowed=True, risk_score=0, reason=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="reason must be str"):
        d.validate()


def test_decision_validate_rejects_non_str_violated_principle() -> None:
    d = Decision(allowed=True, risk_score=0, reason="ok", violated_principle=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="violated_principle must be str"):
        d.validate()


def test_decision_validate_rejects_non_str_mode() -> None:
    d = Decision(allowed=True, risk_score=0, reason="ok", mode=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mode must be str"):
        d.validate()


def test_decision_validate_rejects_bad_abi_version() -> None:
    d = Decision(allowed=True, risk_score=0, reason="ok", abi_version="v0")
    with pytest.raises(ValueError, match=POLICY_ABI_VERSION):
        d.validate()


def test_validate_actor_rejects_blank() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        validate_actor(" ")


def test_validate_actor_rejects_non_str() -> None:
    with pytest.raises(ValueError, match="actor must be str"):
        validate_actor(1)


def test_validate_action_request_rejects_non_action() -> None:
    with pytest.raises(ValueError, match="action_request must be ActionRequest"):
        validate_action_request({"raw_input": "x"})  # type: ignore[arg-type]
