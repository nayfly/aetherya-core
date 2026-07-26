from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetherya.actions import ActionRequest
from aetherya.api import AetheryaAPI, APISettings, _as_action_request
from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.parser import parse_user_input
from aetherya.pipeline import run_pipeline, run_pipeline_structured


def _core() -> Constitution:
    return Constitution(
        [Principle("Non-harm", "Do not cause harm", priority=1, keywords=["harm"], risk=90)],
        use_semantic=False,
    )


# ---------------------------------------------------------------------------
# Parser: parameter values must keep their case
# ---------------------------------------------------------------------------


def test_parameter_values_preserve_case() -> None:
    """
    Regression: values were extracted from a lowercased copy of the input, so
    `param.path=/tmp/MyFile.TXT` was recorded as `/tmp/myfile.txt` — a different
    file on any case-sensitive filesystem. The audit trail then described an
    action other than the one authorised.
    """
    action = parse_user_input("mode:operative tool:shell param.path=/tmp/MyFile.TXT")
    assert action.parameters["path"] == "/tmp/MyFile.TXT"


def test_target_preserves_case() -> None:
    action = parse_user_input("mode:operative tool:filesystem target:/srv/DataStore")
    assert action.target == "/srv/DataStore"


def test_base64_style_values_survive_intact() -> None:
    """Signed proofs are hex today, but a base64 encoding must not be corrupted."""
    action = parse_user_input("mode:operative tool:shell param.confirm_proof=AbC123XyZ+/=")
    assert action.parameters["confirm_proof"] == "AbC123XyZ+/="


def test_parameter_names_are_case_insensitive_and_normalized() -> None:
    action = parse_user_input("mode:operative tool:shell param.Operation=Write")
    assert action.parameters == {"operation": "Write"}


def test_tool_names_are_lowercased_to_match_the_allowlist() -> None:
    action = parse_user_input("mode:operative tool:Shell param.command=ls")
    assert action.tool == "shell"


def test_case_preserving_values_reach_the_audit_trail(tmp_path: Path) -> None:
    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    raw = "mode:operative tool:filesystem param.path=/tmp/MyFile.TXT param.operation=write"

    run_pipeline(raw, _core(), "robert", cfg, audit=AuditLogger(str(audit_path)))

    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert "/tmp/MyFile.TXT" in event["action"]


# ---------------------------------------------------------------------------
# Structured pipeline entry point
# ---------------------------------------------------------------------------


def test_structured_entry_skips_the_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point: no text classification in the trust path."""
    import aetherya.pipeline as pipeline_module

    def _must_not_be_called(_text: str) -> ActionRequest:
        raise AssertionError("parser invoked on the structured path")

    monkeypatch.setattr(pipeline_module, "parse_user_input", _must_not_be_called)

    action = ActionRequest(
        raw_input="write the config file",
        intent="operate",
        mode_hint="operative",
        tool="filesystem",
        target="/tmp/MyDir",
        parameters={"path": "/tmp/MyFile.TXT", "operation": "write"},
    )
    decision = run_pipeline_structured(
        action, _core(), "robert", load_policy_config("config/policy.yaml")
    )
    assert decision.state in {"allow", "log_only", "escalate", "deny", "hard_deny"}


def test_structured_input_still_passes_the_abi_contract() -> None:
    cfg = load_policy_config("config/policy.yaml")
    bad = ActionRequest(raw_input="x", intent="not-a-valid-intent")
    decision = run_pipeline_structured(bad, _core(), "robert", cfg)

    assert decision.allowed is False
    assert "fail_closed:action_request" in decision.reason


def test_structured_input_cannot_lie_its_way_past_the_guards() -> None:
    """
    Declaring `intent="ask"` on a destructive payload must not bypass anything:
    ProceduralGuard reads the raw input and IntentEscalation re-derives intent.
    """
    cfg = load_policy_config("config/policy.yaml")
    action = ActionRequest(
        raw_input="dd if=/dev/zero of=/dev/sda",
        intent="ask",
        mode_hint="consultive",
    )
    decision = run_pipeline_structured(action, _core(), "robert", cfg)

    assert decision.allowed is False
    assert decision.state == "hard_deny"


def test_structured_and_raw_paths_agree_on_an_equivalent_request() -> None:
    cfg = load_policy_config("config/policy.yaml")
    raw = "mode:operative tool:shell param.command=ls"

    from_raw = run_pipeline(raw, _core(), "robert", cfg)
    from_structured = run_pipeline_structured(parse_user_input(raw), _core(), "robert", cfg)
    assert from_raw.to_dict() == from_structured.to_dict()


def test_action_raw_input_wins_over_the_positional_argument() -> None:
    cfg = load_policy_config("config/policy.yaml")
    action = ActionRequest(raw_input="rm -rf /", intent="operate", mode_hint="operative")
    decision = run_pipeline("something harmless", _core(), "robert", cfg, action=action)

    assert decision.state == "hard_deny"


# ---------------------------------------------------------------------------
# HTTP API surface
# ---------------------------------------------------------------------------


def _api(tmp_path: Path) -> AetheryaAPI:
    return AetheryaAPI(APISettings(audit_path=tmp_path / "decisions.jsonl"))


def test_api_accepts_a_structured_action(tmp_path: Path) -> None:
    code, body = _api(tmp_path).decide(
        {
            "action": {
                "raw_input": "write the config file",
                "intent": "operate",
                "mode_hint": "operative",
                "tool": "filesystem",
                "target": "/tmp/MyDir",
                "parameters": {"path": "/tmp/MyFile.TXT", "operation": "write"},
            },
            "actor": "robert",
        }
    )
    assert code == 200
    assert body["meta"]["input_mode"] == "structured"


def test_api_still_accepts_raw_text(tmp_path: Path) -> None:
    code, body = _api(tmp_path).decide({"raw_input": "help user safely", "actor": "robert"})
    assert code == 200
    assert body["meta"]["input_mode"] == "raw_text"


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        ({"action": {"intent": "operate"}}, "action.raw_input must be str"),
        ({"action": {"raw_input": "x"}}, "action.intent must be str"),
        ({"action": {"raw_input": "x", "intent": "bogus"}}, "intent must be one of"),
        (
            {"action": {"raw_input": "x", "intent": "ask", "parameters": []}},
            "must be a JSON object",
        ),
        ({"action": "not-an-object"}, "action must be a JSON object"),
    ],
)
def test_api_rejects_malformed_structured_actions(
    tmp_path: Path, payload: dict[str, object], expected_error: str
) -> None:
    code, body = _api(tmp_path).decide({**payload, "actor": "robert"})
    assert code == 400
    assert expected_error in body["error"]


def test_as_action_request_rejects_non_string_parameter_keys() -> None:
    with pytest.raises(ValueError, match="action.parameters keys must be str"):
        _as_action_request({"raw_input": "x", "intent": "ask", "parameters": {1: "v"}})


def test_as_action_request_treats_null_parameters_as_empty() -> None:
    action = _as_action_request({"raw_input": "x", "intent": "ask", "parameters": None})
    assert action.parameters == {}
