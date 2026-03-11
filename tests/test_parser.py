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


def test_parser_question_with_operative_keyword_is_still_ask() -> None:
    action = parse_user_input("How do I run a Docker container?")
    assert action.intent == "ask"
    assert action.mode_hint == "consultive"


def test_parser_operative_verb_without_question_is_operate() -> None:
    action = parse_user_input("run delete.sh")
    assert action.intent == "operate"


def test_parser_what_question_with_dangerous_keyword_is_ask() -> None:
    action = parse_user_input("What does rm -rf do?")
    assert action.intent == "ask"
    assert action.mode_hint == "consultive"


def test_parser_execute_command_is_operate() -> None:
    action = parse_user_input("execute backup.sh")
    assert action.intent == "operate"


def test_parser_trailing_question_mark_forces_ask() -> None:
    action = parse_user_input("Can you delete all logs?")
    assert action.intent == "ask"
    assert action.mode_hint == "consultive"


def test_parser_interrogative_without_question_mark_forces_ask() -> None:
    action = parse_user_input("what is the current disk usage")
    assert action.intent == "ask"
