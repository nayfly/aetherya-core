from __future__ import annotations

from aetherya.actions import ActionRequest
from aetherya.constitution import Constitution, Principle


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
