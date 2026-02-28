from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetherya.explainability import ExplainabilityEngine
from aetherya.explainability_report import (
    build_html_report,
    load_audit_events,
    main,
    render_html_from_audit,
    render_html_from_event,
)
from aetherya.risk import RiskAggregate, RiskDecision, RiskSignal


def make_explainability() -> dict:
    signals = [
        RiskSignal(source="constitution", score=40, confidence=1.0, reason="policy"),
        RiskSignal(source="procedural_guard", score=20, confidence=0.5, reason="guard"),
    ]
    aggregate = RiskAggregate(
        total_score=50,
        decision=RiskDecision.REQUIRE_CONFIRM,
        reasons=["policy", "guard"],
        breakdown=signals,
        top_signal=signals[0],
    )
    return ExplainabilityEngine().build(
        signals=signals,
        aggregate=aggregate,
        mode="operative",
        weights={"constitution": 1.0, "procedural_guard": 1.0},
        thresholds={"deny_at": 80, "confirm_at": 50, "log_only_at": 0},
        aggregate_decision=aggregate.decision.value,
        effective_risk_decision=aggregate.decision.value,
        state="escalate",
        allowed=False,
        reason="escalate: policy",
        violated_principle="Caution",
        confirmation=None,
    )


def make_event() -> dict:
    return {
        "event_id": "evt-1",
        "decision_id": "sha256:dec",
        "policy_fingerprint": "sha256:policy",
        "ts": "2026-02-28T12:00:00Z",
        "actor": "robert",
        "action": 'run "critical"',
        "decision": {
            "allowed": False,
            "risk_score": 50,
            "reason": "escalate: policy",
            "violated_principle": "Caution",
            "mode": "operative",
            "state": "escalate",
            "abi_version": "v1",
        },
        "context": {
            "explainability": make_explainability(),
        },
    }


def test_build_html_report_contains_sections_and_mermaid() -> None:
    event = make_event()
    mermaid = "flowchart LR\nA-->B\n"
    report = build_html_report(event=event, mermaid=mermaid, title="Test Report")
    assert "<h2>Event Metadata</h2>" in report
    assert "<h2>Decision Summary</h2>" in report
    assert "<h2>Explainability Summary</h2>" in report
    assert "<h2>Contributors</h2>" in report
    assert "<h2>Mermaid Graph</h2>" in report
    assert "flowchart LR" in report
    assert "Test Report" in report


def test_build_html_report_escapes_html_sensitive_content() -> None:
    event = make_event()
    event["action"] = "<script>alert(1)</script>"
    report = build_html_report(event=event, mermaid='flowchart LR\nA["x"]-->B\n')
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report


def test_build_html_report_handles_invalid_contributors_payload() -> None:
    event = make_event()
    event["context"]["explainability"]["contributors"] = "bad"
    report = build_html_report(event=event, mermaid="flowchart LR\nA-->B\n")
    assert "invalid contributors payload" in report


def test_render_html_from_event_renders_using_mermaid_from_context() -> None:
    report = render_html_from_event(make_event(), title="From Event")
    assert "From Event" in report
    assert "flowchart LR" in report


def test_load_audit_events_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("{bad json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_audit_events(path)


def test_load_audit_events_rejects_non_object_payload(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_audit_events(path)


def test_load_audit_events_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text('\n{"a":1}\n\n{"b":2}\n', encoding="utf-8")
    events = load_audit_events(path)
    assert len(events) == 2


def test_render_html_from_audit_uses_latest_event_by_default(tmp_path: Path) -> None:
    event = make_event()
    audit_path = tmp_path / "decisions.jsonl"
    audit_path.write_text(
        json.dumps({"context": {"explainability": {"graph": {"nodes": [], "edges": []}}}})
        + "\n"
        + json.dumps(event)
        + "\n",
        encoding="utf-8",
    )
    report = render_html_from_audit(audit_path)
    assert "evt-1" in report
    assert "sha256:dec" in report


def test_build_html_report_handles_non_mapping_event() -> None:
    report = build_html_report(  # type: ignore[arg-type]
        event="not-a-mapping",
        mermaid="flowchart LR\nA-->B\n",
    )
    assert "Event Metadata" in report
    assert "invalid contributors payload" in report


def test_build_html_report_shows_no_contributors_row() -> None:
    event = make_event()
    event["context"]["explainability"]["contributors"] = []
    report = build_html_report(event=event, mermaid="flowchart LR\nA-->B\n")
    assert "no contributors" in report


def test_build_html_report_shows_invalid_contributor_item_row() -> None:
    event = make_event()
    event["context"]["explainability"]["contributors"] = ["bad-item"]
    report = build_html_report(event=event, mermaid="flowchart LR\nA-->B\n")
    assert "invalid contributor item" in report


def test_build_html_report_includes_extra_summary_keys() -> None:
    event = make_event()
    event["context"]["explainability"]["summary"]["z_extra"] = "value"
    report = build_html_report(event=event, mermaid="flowchart LR\nA-->B\n")
    assert "z_extra" in report


def test_main_writes_html_report_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    event = make_event()
    audit_path = tmp_path / "decisions.jsonl"
    output_path = tmp_path / "report.html"
    audit_path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    code = main(
        [
            "--audit-path",
            str(audit_path),
            "--event-index",
            "-1",
            "--output",
            str(output_path),
            "--title",
            "Audit Report",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "wrote report:" in captured.out
    assert output_path.exists()
    html_report = output_path.read_text(encoding="utf-8")
    assert "Audit Report" in html_report
    assert "flowchart LR" in html_report


def test_main_returns_error_code_for_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--audit-path", "missing.jsonl"])
    captured = capsys.readouterr()
    assert code == 2
    assert "error:" in captured.err
