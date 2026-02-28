from __future__ import annotations

from aetherya.actions import ActionRequest
from aetherya.capability_gate import CapabilityGate
from aetherya.config import CapabilityActorConfig, CapabilityMatrixConfig, CapabilityRoleConfig


def make_capability_gate(
    *,
    enabled: bool = True,
    default_allow: bool = False,
) -> CapabilityGate:
    cfg = CapabilityMatrixConfig(
        enabled=enabled,
        default_allow=default_allow,
        roles={
            "operator": CapabilityRoleConfig(
                tools=["shell", "filesystem"],
                operations=["read", "write", "list"],
            )
        },
        actors={
            "robert": CapabilityActorConfig(
                roles=["operator"],
                tools=[],
                operations=[],
            )
        },
    )
    return CapabilityGate(cfg)


def test_capability_gate_ignores_non_operate_intent() -> None:
    gate = make_capability_gate()
    action = ActionRequest(raw_input="help", intent="ask")
    assert gate.evaluate(actor="robert", action=action) is None


def test_capability_gate_blocks_unknown_actor_when_default_deny() -> None:
    gate = make_capability_gate(default_allow=False)
    action = ActionRequest(raw_input="run", intent="operate", tool="shell")
    result = gate.evaluate(actor="intruder", action=action)
    assert result is not None
    assert "capability_unknown_actor" in result["tags"]


def test_capability_gate_allows_unknown_actor_when_default_allow() -> None:
    gate = make_capability_gate(default_allow=True)
    action = ActionRequest(raw_input="run", intent="operate", tool="shell")
    assert gate.evaluate(actor="intruder", action=action) is None


def test_capability_gate_blocks_disallowed_tool() -> None:
    gate = make_capability_gate()
    action = ActionRequest(raw_input="run", intent="operate", tool="http")
    result = gate.evaluate(actor="robert", action=action)
    assert result is not None
    assert "capability_tool_denied" in result["tags"]


def test_capability_gate_blocks_disallowed_operation() -> None:
    gate = make_capability_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        parameters={"operation": "delete"},
    )
    result = gate.evaluate(actor="robert", action=action)
    assert result is not None
    assert "capability_operation_denied" in result["tags"]


def test_capability_gate_allows_actor_role_capabilities() -> None:
    gate = make_capability_gate()
    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        parameters={"operation": "read"},
    )
    assert gate.evaluate(actor="robert", action=action) is None


def test_capability_gate_disabled_returns_none() -> None:
    gate = make_capability_gate(enabled=False)
    action = ActionRequest(raw_input="run", intent="operate", tool="docker")
    assert gate.evaluate(actor="intruder", action=action) is None


def test_capability_gate_ignores_unknown_role_reference() -> None:
    cfg = CapabilityMatrixConfig(
        enabled=True,
        default_allow=False,
        roles={},
        actors={
            "robert": CapabilityActorConfig(
                roles=["missing_role"],
                tools=[],
                operations=[],
            )
        },
    )
    gate = CapabilityGate(cfg)
    action = ActionRequest(raw_input="run", intent="operate", tool="shell")
    result = gate.evaluate(actor="robert", action=action)
    assert result is not None
    assert "capability_unknown_role" in result["tags"]


def test_capability_gate_known_actor_without_capabilities_denies_tool() -> None:
    cfg = CapabilityMatrixConfig(
        enabled=True,
        default_allow=False,
        roles={},
        actors={
            "robert": CapabilityActorConfig(
                roles=[],
                tools=[],
                operations=[],
            )
        },
    )
    gate = CapabilityGate(cfg)
    action = ActionRequest(raw_input="run", intent="operate", tool="shell")
    result = gate.evaluate(actor="robert", action=action)
    assert result is not None
    assert "capability_tool_denied" in result["tags"]
