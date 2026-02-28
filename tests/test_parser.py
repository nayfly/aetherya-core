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
