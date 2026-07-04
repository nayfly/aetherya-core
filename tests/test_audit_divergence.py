from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aetherya.audit_divergence import (
    DivergenceRecord,
    _action_preview,
    _clean_str,
    _print_text_report,
    _round_rate,
    _safe_int,
    build_divergence_report,
    extract_divergence_records,
    main,
)


def _shadow_event(
    *,
    risk_delta: int = 0,
    absolute: int | None = None,
    state_mismatch: bool = False,
    suggested_state: str = "allow",
    suggested_risk: int = 0,
    core_state: str = "allow",
    core_risk: int = 0,
    evaluation: dict[str, Any] | None = None,
    provider: str = "openai",
    action: str = "help user",
) -> dict[str, Any]:
    shadow: dict[str, Any] = {
        "enabled": True,
        "provider": provider,
        "dry_run": False,
        "shadow_suggestion": {
            "suggested_state": suggested_state,
            "suggested_risk_score": suggested_risk,
        },
        "ethical_divergence": {
            "state_mismatch": state_mismatch,
            "risk_delta": risk_delta,
            "absolute_risk_delta": abs(risk_delta) if absolute is None else absolute,
        },
    }
    if evaluation is not None:
        shadow["evaluation"] = evaluation
    return {
        "event_id": "ev-1",
        "actor": "robert",
        "action": action,
        "decision": {"state": core_state, "risk_score": core_risk},
        "context": {"llm_shadow": shadow},
    }


def write_audit(tmp_path: Path, events: list[dict[str, Any]]) -> Path:
    path = tmp_path / "decisions.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_clean_str_variants() -> None:
    assert _clean_str("  ok  ") == "ok"
    assert _clean_str("   ") is None
    assert _clean_str(42) is None


def test_safe_int_variants() -> None:
    assert _safe_int(7) == 7
    assert _safe_int(True) is None
    assert _safe_int("7") is None


def test_round_rate_zero_denominator() -> None:
    assert _round_rate(1, 0) == 0.0
    assert _round_rate(1, 3) == 0.3333


def test_action_preview_variants() -> None:
    assert _action_preview(None) is None
    assert _action_preview("short") == "short"
    long_action = "x" * 200
    preview = _action_preview(long_action)
    assert preview is not None
    assert preview.endswith("...")
    assert len(preview) == 83


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_extract_skips_events_without_shadow() -> None:
    events: list[dict[str, Any]] = [
        {"actor": "robert", "action": "hi"},
        {"context": "not-a-dict"},
        {"context": {"mode": "operative"}},
        {"context": {"llm_shadow": "not-a-dict"}},
    ]
    records, errors = extract_divergence_records(events)
    assert records == []
    assert errors == 0


def test_extract_counts_shadow_errors() -> None:
    events = [
        {"context": {"llm_shadow": {"enabled": True, "error_type": "RuntimeError"}}},
        _shadow_event(risk_delta=10),
    ]
    records, errors = extract_divergence_records(events)
    assert errors == 1
    assert len(records) == 1
    assert records[0].line_no == 2


def test_extract_full_record_with_evaluation() -> None:
    events = [
        _shadow_event(
            risk_delta=-30,
            state_mismatch=True,
            suggested_state="deny",
            suggested_risk=80,
            core_state="allow",
            core_risk=10,
            evaluation={
                "parse_success": True,
                "reasoning": "irreversible action",
                "flags": ["harmful", "irreversible", 42],
            },
        )
    ]
    records, errors = extract_divergence_records(events)
    assert errors == 0
    record = records[0]
    assert record.event_id == "ev-1"
    assert record.actor == "robert"
    assert record.provider == "openai"
    assert record.dry_run is False
    assert record.core_state == "allow"
    assert record.core_risk_score == 10
    assert record.suggested_state == "deny"
    assert record.suggested_risk_score == 80
    assert record.risk_delta == -30
    assert record.absolute_risk_delta == 30
    assert record.state_mismatch is True
    assert record.parse_success is True
    assert record.flags == ("harmful", "irreversible")


def test_extract_tolerates_malformed_blocks() -> None:
    events: list[dict[str, Any]] = [
        {
            "context": {
                "llm_shadow": {
                    "shadow_suggestion": "not-a-dict",
                    "evaluation": "not-a-dict",
                    "ethical_divergence": {
                        "risk_delta": "not-an-int",
                        "state_mismatch": False,
                    },
                }
            },
            "decision": "not-a-dict",
        }
    ]
    records, errors = extract_divergence_records(events)
    assert errors == 0
    record = records[0]
    assert record.risk_delta == 0
    assert record.absolute_risk_delta == 0
    assert record.suggested_state is None
    assert record.core_state is None
    assert record.parse_success is None
    assert record.flags == ()
    assert record.dry_run is None


def test_extract_flags_not_a_list_yields_empty() -> None:
    events = [_shadow_event(evaluation={"parse_success": False, "flags": "harmful"})]
    records, _errors = extract_divergence_records(events)
    assert records[0].parse_success is False
    assert records[0].flags == ()


def test_extract_absolute_falls_back_to_abs_of_delta() -> None:
    event = _shadow_event(risk_delta=-12)
    del event["context"]["llm_shadow"]["ethical_divergence"]["absolute_risk_delta"]
    records, _errors = extract_divergence_records([event])
    assert records[0].absolute_risk_delta == 12


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _record(**overrides: Any) -> DivergenceRecord:
    base: dict[str, Any] = {
        "line_no": 1,
        "event_id": "ev-1",
        "actor": "robert",
        "action": "help user",
        "provider": "openai",
        "dry_run": False,
        "core_state": "allow",
        "core_risk_score": 10,
        "suggested_state": "allow",
        "suggested_risk_score": 10,
        "risk_delta": 0,
        "absolute_risk_delta": 0,
        "state_mismatch": False,
        "parse_success": True,
        "flags": (),
    }
    base.update(overrides)
    return DivergenceRecord(**base)


def test_report_empty_records() -> None:
    report = build_divergence_report(
        [],
        audit_path="a.jsonl",
        events_total=3,
        shadow_errors=1,
        top=5,
        min_abs_delta=0,
    )
    assert report["shadow_evaluations"] == 0
    assert report["shadow_errors"] == 1
    assert report["state_mismatch_rate"] == 0.0
    assert report["risk_delta"] == {"mean": 0.0, "mean_absolute": 0.0, "max_absolute": 0}
    assert report["parse"] == {"evaluated": 0, "success": 0, "success_rate": 0.0}
    assert report["flags"] == {}
    assert report["top_divergences"] == []


def test_report_aggregates_stats_and_flags() -> None:
    records = [
        _record(line_no=1, risk_delta=20, absolute_risk_delta=20, flags=("harmful",)),
        _record(
            line_no=2,
            risk_delta=-40,
            absolute_risk_delta=40,
            state_mismatch=True,
            parse_success=False,
            flags=("harmful", "pii_exposure"),
        ),
        _record(line_no=3, parse_success=None),
    ]
    report = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=5,
        shadow_errors=0,
        top=5,
        min_abs_delta=0,
    )
    assert report["shadow_evaluations"] == 3
    assert report["state_mismatches"] == 1
    assert report["state_mismatch_rate"] == 0.3333
    assert report["risk_delta"]["mean"] == round((20 - 40 + 0) / 3, 4)
    assert report["risk_delta"]["mean_absolute"] == 20.0
    assert report["risk_delta"]["max_absolute"] == 40
    assert report["parse"] == {"evaluated": 2, "success": 1, "success_rate": 0.5}
    assert report["flags"] == {"harmful": 2, "pii_exposure": 1}
    assert [item["line_no"] for item in report["top_divergences"]] == [2, 1, 3]


def test_report_min_abs_delta_filters_top_list() -> None:
    records = [
        _record(line_no=1, risk_delta=5, absolute_risk_delta=5),
        _record(line_no=2, risk_delta=50, absolute_risk_delta=50),
    ]
    report = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=2,
        shadow_errors=0,
        top=5,
        min_abs_delta=10,
    )
    assert [item["line_no"] for item in report["top_divergences"]] == [2]
    # Stats still consider all records, only the top list is filtered.
    assert report["shadow_evaluations"] == 2


def test_report_top_limits_and_negative_top_is_empty() -> None:
    records = [
        _record(line_no=i, risk_delta=i * 10, absolute_risk_delta=i * 10) for i in range(1, 5)
    ]
    limited = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=4,
        shadow_errors=0,
        top=2,
        min_abs_delta=0,
    )
    assert [item["line_no"] for item in limited["top_divergences"]] == [4, 3]

    negative = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=4,
        shadow_errors=0,
        top=-1,
        min_abs_delta=0,
    )
    assert negative["top_divergences"] == []


def test_report_truncates_long_actions() -> None:
    records = [_record(action="y" * 200, risk_delta=10, absolute_risk_delta=10)]
    report = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=1,
        shadow_errors=0,
        top=1,
        min_abs_delta=0,
    )
    action = report["top_divergences"][0]["action"]
    assert action.endswith("...")
    assert len(action) == 83


# ---------------------------------------------------------------------------
# Text output
# ---------------------------------------------------------------------------


def test_print_text_report_full(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        _record(
            line_no=1,
            risk_delta=-40,
            absolute_risk_delta=40,
            state_mismatch=True,
            suggested_state="deny",
            suggested_risk_score=50,
            flags=("harmful",),
        )
    ]
    report = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=1,
        shadow_errors=0,
        top=1,
        min_abs_delta=0,
    )
    _print_text_report(report)
    out = capsys.readouterr().out
    assert "shadow_evaluations=1" in out
    assert "flags harmful=1" in out
    assert "divergence line=1" in out
    assert "core=allow/10 shadow=deny/50" in out


def test_print_text_report_handles_missing_values(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        _record(
            line_no=1,
            event_id=None,
            core_state=None,
            core_risk_score=None,
            suggested_state=None,
            suggested_risk_score=None,
            risk_delta=10,
            absolute_risk_delta=10,
        )
    ]
    report = build_divergence_report(
        records,
        audit_path="a.jsonl",
        events_total=1,
        shadow_errors=0,
        top=1,
        min_abs_delta=0,
    )
    _print_text_report(report)
    out = capsys.readouterr().out
    assert "event_id=-" in out
    assert "core=-/- shadow=-/-" in out
    assert "flags" not in out


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_missing_file_returns_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--audit-path", str(tmp_path / "missing.jsonl")])
    assert exit_code == 2
    assert "error:" in capsys.readouterr().err


def test_main_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit_path = write_audit(
        tmp_path,
        [
            {"actor": "robert", "action": "no shadow"},
            {"context": {"llm_shadow": {"enabled": True, "error_type": "TimeoutError"}}},
            _shadow_event(
                risk_delta=35,
                state_mismatch=True,
                suggested_state="deny",
                suggested_risk=45,
                core_risk=10,
                evaluation={"parse_success": True, "reasoning": "risky", "flags": ["harmful"]},
            ),
        ],
    )
    exit_code = main(["--audit-path", str(audit_path), "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["events_total"] == 3
    assert report["shadow_evaluations"] == 1
    assert report["shadow_errors"] == 1
    assert report["state_mismatches"] == 1
    assert report["parse"]["success_rate"] == 1.0
    assert report["flags"] == {"harmful": 1}
    assert report["top_divergences"][0]["risk_delta"] == 35


def test_main_text_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit_path = write_audit(tmp_path, [_shadow_event(risk_delta=5)])
    exit_code = main(["--audit-path", str(audit_path)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "events=1 shadow_evaluations=1 shadow_errors=0" in out


def test_main_min_abs_delta_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit_path = write_audit(
        tmp_path,
        [_shadow_event(risk_delta=5), _shadow_event(risk_delta=60)],
    )
    exit_code = main(
        ["--audit-path", str(audit_path), "--min-abs-delta", "50", "--top", "10", "--json"]
    )
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["top_divergences"]) == 1
    assert report["top_divergences"][0]["absolute_risk_delta"] == 60
