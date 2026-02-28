from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetherya.explainability import ExplainabilityEngine
from aetherya.explainability_render import (
    extract_explainability,
    load_audit_events,
    main,
    render_mermaid,
    render_mermaid_from_audit,
    render_mermaid_from_event,
    select_event,
)
from aetherya.risk import RiskAggregate, RiskDecision, RiskSignal


def make_explainability_graph() -> dict:
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


def test_render_mermaid_generates_flowchart_with_labels() -> None:
    mermaid = render_mermaid(make_explainability_graph())
    assert mermaid.startswith("flowchart LR")
    assert "RiskAggregate" in mermaid
    assert "PolicyDecision" in mermaid
    assert "contributes_to" in mermaid


def test_extract_explainability_raises_when_missing() -> None:
    with pytest.raises(ValueError, match="does not contain explainability"):
        extract_explainability({"context": {}})


def test_render_mermaid_from_event_uses_context_graph() -> None:
    event = {"context": {"explainability": make_explainability_graph()}}
    mermaid = render_mermaid_from_event(event)
    assert "flowchart LR" in mermaid


def test_load_audit_events_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("{bad json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_audit_events(path)


def test_load_audit_events_skips_blank_lines_and_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text('\n{"ok":1}\n[]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        load_audit_events(path)


def test_select_event_raises_on_empty_list() -> None:
    with pytest.raises(ValueError, match="contains no events"):
        select_event([], 0)


def test_select_event_raises_on_out_of_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        select_event([{"id": 1}], 5)


def test_select_event_supports_negative_index() -> None:
    events = [{"id": 1}, {"id": 2}]
    event = select_event(events, -1)
    assert event["id"] == 2


def test_render_mermaid_from_audit_reads_latest_event(tmp_path: Path) -> None:
    explainability = make_explainability_graph()
    path = tmp_path / "decisions.jsonl"
    path.write_text(
        '{"context":{"explainability":{"graph":{"nodes":[],"edges":[]}}}}\n'
        + '{"context":{"explainability":'
        + json.dumps(explainability)
        + "}}\n",
        encoding="utf-8",
    )
    mermaid = render_mermaid_from_audit(path, -1)
    assert "flowchart LR" in mermaid


def test_render_mermaid_rejects_edge_with_unknown_node() -> None:
    graph = {
        "graph": {
            "nodes": [{"id": "a", "label": "A", "type": "signal", "data": {}}],
            "edges": [{"from": "a", "to": "missing", "type": "x", "data": {}}],
        }
    }
    with pytest.raises(ValueError, match="unknown node"):
        render_mermaid(graph)


def test_render_mermaid_rejects_missing_graph() -> None:
    with pytest.raises(ValueError, match="graph is missing"):
        render_mermaid({})


def test_render_mermaid_rejects_non_list_nodes() -> None:
    with pytest.raises(ValueError, match="nodes must be list"):
        render_mermaid({"graph": {"nodes": "bad", "edges": []}})


def test_render_mermaid_rejects_non_list_edges() -> None:
    with pytest.raises(ValueError, match="edges must be list"):
        render_mermaid({"graph": {"nodes": [], "edges": "bad"}})


def test_render_mermaid_rejects_non_object_node() -> None:
    with pytest.raises(ValueError, match="node must be object"):
        render_mermaid({"graph": {"nodes": ["bad"], "edges": []}})


def test_render_mermaid_rejects_empty_node_id() -> None:
    with pytest.raises(ValueError, match="node id is required"):
        render_mermaid({"graph": {"nodes": [{"id": "  "}], "edges": []}})


def test_render_mermaid_rejects_non_object_edge() -> None:
    graph = {
        "graph": {
            "nodes": [{"id": "a", "label": "A"}],
            "edges": ["bad"],
        }
    }
    with pytest.raises(ValueError, match="edge must be object"):
        render_mermaid(graph)


def test_render_mermaid_handles_special_node_ids_and_bad_ratio() -> None:
    graph = {
        "graph": {
            "nodes": [
                {
                    "id": "!!!",
                    "label": 'Node "A"',
                    "type": "signal",
                    "data": {"weighted_score": 5, "contribution_ratio": "bad"},
                },
                {
                    "id": "123abc",
                    "label": "Node B",
                    "type": "decision_state",
                    "data": {"state": "allow", "allowed": True},
                },
            ],
            "edges": [
                {
                    "from": "!!!",
                    "to": "123abc",
                    "type": "edge",
                    "data": {"weighted_score": 1, "contribution_ratio": "bad"},
                }
            ],
        }
    }
    mermaid = render_mermaid(graph)
    assert 'Node \\"A\\"' in mermaid
    assert "c=0.00" in mermaid
    assert "n0_node" in mermaid
    assert "n1_n_123abc" in mermaid


def test_extract_explainability_rejects_invalid_context_type() -> None:
    with pytest.raises(ValueError, match="context is missing or invalid"):
        extract_explainability({"context": "bad"})


def test_main_writes_output_file(tmp_path: Path) -> None:
    explainability = make_explainability_graph()
    audit_path = tmp_path / "decisions.jsonl"
    audit_path.write_text(
        '{"context":{"explainability":' + json.dumps(explainability) + "}}\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "graph.mmd"
    code = main(
        [
            "--audit-path",
            str(audit_path),
            "--event-index",
            "-1",
            "--output",
            str(output_path),
        ]
    )
    assert code == 0
    assert output_path.exists()
    assert "flowchart LR" in output_path.read_text(encoding="utf-8")


def test_main_prints_to_stdout_when_output_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    explainability = make_explainability_graph()
    audit_path = tmp_path / "decisions.jsonl"
    audit_path.write_text(
        '{"context":{"explainability":' + json.dumps(explainability) + "}}\n",
        encoding="utf-8",
    )
    code = main(["--audit-path", str(audit_path), "--event-index", "-1"])
    captured = capsys.readouterr()
    assert code == 0
    assert "flowchart LR" in captured.out


def test_main_returns_error_code_when_audit_missing(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--audit-path", "missing.jsonl"])
    captured = capsys.readouterr()
    assert code == 2
    assert "error:" in captured.err
