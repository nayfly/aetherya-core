from __future__ import annotations

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


def test_parser_question_with_rm_is_operative() -> None:
    """
    'What does rm -rf do?' contains 'rm' — operative.
    Previously (incorrectly) returned ask/consultive.
    """
    action = parse_user_input("What does rm -rf do?")
    assert action.intent == "operate"
    assert action.mode_hint == "operative"


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
