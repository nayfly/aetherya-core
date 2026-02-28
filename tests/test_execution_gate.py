from __future__ import annotations

from aetherya.actions import ActionRequest
from aetherya.config import ExecutionGateConfig
from aetherya.execution_gate import ExecutionGate


def make_gate(**kwargs) -> ExecutionGate:
    cfg = ExecutionGateConfig(
        enabled=True,
        allowed_tools=["shell", "http"],
        require_target_for_operate=False,
        required_parameters={"shell": ["command"]},
        allowed_parameters={"shell": ["command", "timeout"], "http": ["method", "url", "body"]},
    )
    data = {**cfg.__dict__, **kwargs}
    merged = ExecutionGateConfig(**data)
    return ExecutionGate(merged)


def test_execution_gate_ignores_non_operate_intent() -> None:
    gate = make_gate()
    action = ActionRequest(raw_input="help", intent="ask")
    assert gate.evaluate(action) is None


def test_execution_gate_disabled_returns_none() -> None:
    gate = make_gate(enabled=False)
    action = ActionRequest(raw_input="run", intent="operate")
    assert gate.evaluate(action) is None


def test_execution_gate_missing_tool_blocks() -> None:
    gate = make_gate()
    action = ActionRequest(raw_input="run", intent="operate")
    result = gate.evaluate(action)
    assert result is not None
    assert "missing_tool" in result["tags"]


def test_execution_gate_disallows_unknown_tool() -> None:
    gate = make_gate()
    action = ActionRequest(raw_input="run", intent="operate", tool="docker")
    result = gate.evaluate(action)
    assert result is not None
    assert "tool_not_allowed" in result["tags"]
    assert result["risk_score"] >= 90


def test_execution_gate_requires_target_when_configured() -> None:
    gate = make_gate(require_target_for_operate=True)
    action = ActionRequest(raw_input="run", intent="operate", tool="shell")
    result = gate.evaluate(action)
    assert result is not None
    assert "missing_target" in result["tags"]


def test_execution_gate_requires_params_per_tool() -> None:
    gate = make_gate()
    action = ActionRequest(raw_input="run", intent="operate", tool="shell", target="local")
    result = gate.evaluate(action)
    assert result is not None
    assert "missing_required_parameter" in result["tags"]


def test_execution_gate_blocks_extra_params() -> None:
    gate = make_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="shell",
        target="local",
        parameters={"command": "ls", "evil": "1"},
    )
    result = gate.evaluate(action)
    assert result is not None
    assert "parameter_not_allowed" in result["tags"]


def test_execution_gate_accepts_valid_structured_action() -> None:
    gate = make_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="shell",
        target="local",
        parameters={"command": "ls", "timeout": "10"},
    )
    assert gate.evaluate(action) is None


def test_execution_gate_skips_allowed_param_check_when_not_configured() -> None:
    gate = make_gate(allowed_parameters={})
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="shell",
        target="local",
        parameters={"command": "ls", "unexpected": "ok"},
    )
    assert gate.evaluate(action) is None


def test_execution_gate_allows_confirmation_reserved_params() -> None:
    gate = make_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="shell",
        target="local",
        parameters={
            "command": "ls",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved_for_sensitive_action",
        },
    )
    assert gate.evaluate(action) is None
