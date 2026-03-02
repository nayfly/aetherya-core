from __future__ import annotations

import io
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from aetherya import cli


def _write_policy(tmp_path: Path, mutate) -> Path:  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _read_last_event(path: Path) -> dict:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1])


def test_cli_decide_json_output_basic(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit_path = tmp_path / "decisions.jsonl"
    exit_code = cli.main(
        [
            "decide",
            "help user",
            "--actor",
            "robert",
            "--policy-path",
            "config/policy.yaml",
            "--audit-path",
            str(audit_path),
            "--json",
        ]
    )
    assert exit_code == 0

    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["decision"]["abi_version"] == "v1"
    assert payload["meta"]["wait_shadow"] is True
    assert payload["meta"]["event_id"]
    assert payload["meta"]["decision_id"]


def test_cli_decide_no_wait_shadow_disables_llm_shadow(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy_path = _write_policy(
        tmp_path,
        lambda data: data["llm_shadow"].update(
            {"enabled": True, "provider": "dry_run", "model": "gpt-dry", "max_tokens": 32}
        ),
    )
    audit_path = tmp_path / "decisions.jsonl"

    exit_code = cli.main(
        [
            "decide",
            "help user",
            "--policy-path",
            str(policy_path),
            "--audit-path",
            str(audit_path),
            "--no-wait-shadow",
            "--json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["meta"]["wait_shadow"] is False
    assert payload["meta"]["llm_shadow_enabled_config"] is True
    assert payload["meta"]["llm_shadow_enabled_effective"] is False

    event = _read_last_event(audit_path)
    assert "llm_shadow" not in event["context"]


def test_cli_decide_candidate_response_triggers_output_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path = tmp_path / "decisions.jsonl"
    exit_code = cli.main(
        [
            "decide",
            "help user",
            "--candidate-response",
            "you are an idiot",
            "--audit-path",
            str(audit_path),
            "--json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["decision"]["allowed"] is False
    assert payload["decision"]["state"] == "hard_deny"
    assert payload["meta"]["candidate_response_present"] is True

    event = _read_last_event(audit_path)
    assert event["context"]["output_gate"]["blocked"] is True


def test_cli_decide_blank_candidate_response_is_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path = tmp_path / "decisions.jsonl"
    exit_code = cli.main(
        [
            "decide",
            "help user",
            "--candidate-response",
            "   ",
            "--audit-path",
            str(audit_path),
            "--json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["meta"]["candidate_response_present"] is False

    event = _read_last_event(audit_path)
    assert "output_gate" not in event["context"]


def test_cli_decide_loads_constitution_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    constitution_path = tmp_path / "constitution.yaml"
    constitution_path.write_text(
        yaml.safe_dump(
            {
                "principles": [
                    {
                        "name": "CustomRule",
                        "description": "custom deny for tests",
                        "priority": 1,
                        "keywords": ["forbidden_token"],
                        "risk": 99,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    exit_code = cli.main(
        [
            "decide",
            "forbidden_token now",
            "--constitution-path",
            str(constitution_path),
            "--json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["decision"]["violated_principle"] == "CustomRule"


def test_cli_decide_reads_input_from_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeStdin(io.StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sys.stdin", FakeStdin("help user from stdin\n"))
    exit_code = cli.main(["decide", "--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["decision"]["abi_version"] == "v1"


def test_cli_resolve_raw_input_inline_non_empty_returns_cleaned() -> None:
    assert cli._resolve_raw_input(None, "  help user  ") == "help user"  # noqa: SLF001


def test_cli_decide_rejects_conflicting_input_sources(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["decide", "a", "--input", "b"])
    assert exit_code == 1
    assert "provide either positional raw_input or --input" in capsys.readouterr().err


def test_cli_decide_text_output_and_event_ids(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path = tmp_path / "decisions.jsonl"
    exit_code = cli.main(["decide", "help user", "--audit-path", str(audit_path)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "allowed=" in out
    assert "event_id=" in out
    assert "decision_id=" in out


def test_cli_decide_text_output_without_audit_skips_event_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["decide", "--input", "help user"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "allowed=" in out
    assert "event_id=" not in out


def test_cli_decide_stdin_tty_missing_input_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class TtyStdin(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", TtyStdin(""))
    exit_code = cli.main(["decide"])
    assert exit_code == 1
    assert "missing raw_input" in capsys.readouterr().err


def test_cli_decide_stdin_empty_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class PipeStdin(io.StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sys.stdin", PipeStdin("   \n"))
    exit_code = cli.main(["decide"])
    assert exit_code == 1
    assert "stdin input is empty" in capsys.readouterr().err


def test_cli_decide_rejects_empty_inline_or_positional_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code_a = cli.main(["decide", "--input", "   "])
    exit_code_b = cli.main(["decide", "   "])
    err = capsys.readouterr().err
    assert exit_code_a == 1
    assert exit_code_b == 1
    assert "--input must be non-empty" in err
    assert "raw_input must be non-empty" in err


def test_cli_main_without_subcommand_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main([])
    assert exit_code == 2
    assert "AETHERYA command-line interface." in capsys.readouterr().err


def test_cli_main_json_error_branch(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["decide", "--input", "   ", "--json"])
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["ok"] is False
    assert payload["error_type"] == "ValueError"


def test_cli_main_system_exit_code_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeParserNone:
        def parse_known_args(self, argv):  # noqa: ANN001, ANN202
            raise SystemExit(None)

    class FakeParserStr:
        def parse_known_args(self, argv):  # noqa: ANN001, ANN202
            raise SystemExit("bad")

    monkeypatch.setattr(cli, "_build_parser", lambda: FakeParserNone())
    assert cli.main(["decide"]) == 1

    monkeypatch.setattr(cli, "_build_parser", lambda: FakeParserStr())
    assert cli.main(["decide"]) == 2


def test_cli_load_constitution_valid_list_payload(tmp_path: Path) -> None:
    path = tmp_path / "constitution.yaml"
    path.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "RuleA",
                    "description": "desc",
                    "keywords": ["x"],
                    "priority": 1,
                    "risk": 20,
                }
            ]
        ),
        encoding="utf-8",
    )
    core = cli._load_constitution(path)  # noqa: SLF001
    assert len(core.principles) == 1
    assert core.principles[0].name == "RuleA"


def test_cli_load_constitution_error_paths(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"
    with pytest.raises(ValueError, match="constitution file not found"):
        cli._load_constitution(missing)  # noqa: SLF001

    bad_payload = tmp_path / "bad_payload.yaml"
    bad_payload.write_text(yaml.safe_dump({"principles": "no-list"}), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a 'principles' list"):
        cli._load_constitution(bad_payload)  # noqa: SLF001

    empty = tmp_path / "empty.yaml"
    empty.write_text(yaml.safe_dump({"principles": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be non-empty"):
        cli._load_constitution(empty)  # noqa: SLF001

    non_mapping = tmp_path / "non_mapping.yaml"
    non_mapping.write_text(yaml.safe_dump({"principles": ["x"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a mapping"):
        cli._load_constitution(non_mapping)  # noqa: SLF001

    empty_name = tmp_path / "empty_name.yaml"
    empty_name.write_text(
        yaml.safe_dump({"principles": [{"name": "", "description": "x"}]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="empty name"):
        cli._load_constitution(empty_name)  # noqa: SLF001

    empty_desc = tmp_path / "empty_desc.yaml"
    empty_desc.write_text(
        yaml.safe_dump({"principles": [{"name": "x", "description": ""}]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="empty description"):
        cli._load_constitution(empty_desc)  # noqa: SLF001

    bad_keywords = tmp_path / "bad_keywords.yaml"
    bad_keywords.write_text(
        yaml.safe_dump({"principles": [{"name": "x", "description": "y", "keywords": "not-list"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="keywords must be a list"):
        cli._load_constitution(bad_keywords)  # noqa: SLF001


def test_cli_helpers_event_and_shadow_branches(tmp_path: Path) -> None:
    assert cli._maybe_read_last_event(None) is None  # noqa: SLF001
    missing = tmp_path / "missing.jsonl"
    assert cli._maybe_read_last_event(missing) is None  # noqa: SLF001

    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    assert cli._maybe_read_last_event(empty) is None  # noqa: SLF001

    non_object = tmp_path / "non_object.jsonl"
    non_object.write_text("[1,2,3]\n", encoding="utf-8")
    assert cli._maybe_read_last_event(non_object) is None  # noqa: SLF001

    cfg = cli.load_policy_config("config/policy.yaml")  # noqa: SLF001
    assert cli._llm_shadow_disabled(cfg, wait_shadow=True) is cfg  # noqa: SLF001

    cfg_disabled = replace(
        cfg,
        llm_shadow=replace(cfg.llm_shadow, enabled=False),
    )
    assert cli._llm_shadow_disabled(cfg_disabled, wait_shadow=False) is cfg_disabled  # noqa: SLF001


def test_cli_main_non_callable_handler_returns_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeParser:
        def parse_known_args(self, argv):  # noqa: ANN001, ANN202
            return SimpleNamespace(handler="bad"), []

        def print_help(self, file=None):  # noqa: ANN001
            print("help", file=file)

    monkeypatch.setattr(cli, "_build_parser", lambda: FakeParser())
    exit_code = cli.main(["decide"])
    assert exit_code == 2
    assert "help" in capsys.readouterr().err


def test_cli_cmd_forward_rejects_invalid_target() -> None:
    with pytest.raises(ValueError, match="invalid wrapped CLI target"):
        cli._cmd_forward(SimpleNamespace(target_main=None, forward_args=[]))  # noqa: SLF001


def test_cli_wrapper_audit_verify_forwards_args(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured["argv"] = list(argv)
        return 7

    monkeypatch.setattr(cli, "audit_verify_main", fake_main)
    exit_code = cli.main(["audit", "verify", "--audit-path", "audit/decisions.jsonl", "--json"])
    assert exit_code == 7
    assert captured["argv"] == ["--audit-path", "audit/decisions.jsonl", "--json"]


def test_cli_wrapper_explainability_render_forwards_args(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured["argv"] = list(argv)
        return 8

    monkeypatch.setattr(cli, "explainability_render_main", fake_main)
    exit_code = cli.main(["explainability", "render", "--audit-path", "audit/decisions.jsonl"])
    assert exit_code == 8
    assert captured["argv"] == ["--audit-path", "audit/decisions.jsonl"]


def test_cli_wrapper_security_gate_forwards_args(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured["argv"] = list(argv)
        return 9

    monkeypatch.setattr(cli, "security_gate_main", fake_main)
    exit_code = cli.main(["security", "gate", "--json"])
    assert exit_code == 9
    assert captured["argv"] == ["--json"]


def test_cli_wrapper_release_verify_artifacts_forwards_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured["argv"] = list(argv)
        return 10

    monkeypatch.setattr(cli, "verify_release_artifacts_main", fake_main)
    exit_code = cli.main(["release", "verify-artifacts", "--expected-commit-sha", "abc"])
    assert exit_code == 10
    assert captured["argv"] == ["--expected-commit-sha", "abc"]


def test_cli_wrapper_benchmark_pipeline_forwards_args(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured["argv"] = list(argv)
        return 11

    monkeypatch.setattr(cli, "pipeline_benchmark_main", fake_main)
    exit_code = cli.main(["benchmark", "pipeline", "--runs", "2"])
    assert exit_code == 11
    assert captured["argv"] == ["--runs", "2"]


def test_cli_wrapper_forwards_args_with_double_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured["argv"] = list(argv)
        return 12

    monkeypatch.setattr(cli, "chaos_benchmark_main", fake_main)
    exit_code = cli.main(["benchmark", "chaos", "--", "--runs", "3", "--json"])
    assert exit_code == 12
    assert captured["argv"] == ["--runs", "3", "--json"]


def test_cli_nested_command_required_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["audit"])
    assert exit_code == 2
    assert "usage: aetherya audit" in capsys.readouterr().err


def test_cli_decide_unknown_argument_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["decide", "help user", "--unknown-flag"])
    assert exit_code == 2
    assert "unrecognized arguments: --unknown-flag" in capsys.readouterr().err
