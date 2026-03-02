from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.pipeline import run_pipeline


def _core() -> Constitution:
    return Constitution(
        [
            Principle(
                "Caution",
                "Need confirmation for sensitive requests",
                priority=1,
                keywords=["sensitive"],
                risk=55,
            )
        ]
    )


def _read_last_event(path: Path) -> dict:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1])


def test_pipeline_output_gate_blocks_toxic_candidate_response(tmp_path: Path) -> None:
    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    decision = run_pipeline(
        "help user",
        constitution=_core(),
        actor="robert",
        cfg=cfg,
        audit=audit,
        response_text="you are an idiot",
    )

    assert decision.allowed is False
    assert decision.state == "hard_deny"
    assert decision.violated_principle == "OutputSafety"
    assert "output toxicity detected" in decision.reason

    event = _read_last_event(audit_path)
    output_gate = event["context"]["output_gate"]
    assert output_gate["blocked"] is True
    assert output_gate["response_hash"].startswith("sha256:")
    assert output_gate["response_length"] == len("you are an idiot")
    assert "idiot" in output_gate["matched_terms"]


def test_pipeline_output_gate_clean_candidate_response_keeps_base_decision(tmp_path: Path) -> None:
    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    base = run_pipeline("help user", constitution=_core(), actor="robert", cfg=cfg)
    with_response = run_pipeline(
        "help user",
        constitution=_core(),
        actor="robert",
        cfg=cfg,
        audit=audit,
        response_text="Thank you, happy to help.",
    )

    assert with_response.allowed == base.allowed
    assert with_response.state == base.state
    assert with_response.risk_score == base.risk_score
    assert with_response.violated_principle == base.violated_principle

    event = _read_last_event(audit_path)
    assert "output_gate" not in event["context"]


def test_pipeline_output_gate_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import aetherya.pipeline as pipeline

    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    class BoomOutputGate:
        def evaluate(self, text: str):  # noqa: ANN001, ANN202
            raise RuntimeError("output gate exploded")

    monkeypatch.setattr(pipeline, "OutputGate", lambda: BoomOutputGate())

    decision = run_pipeline(
        "help user",
        constitution=_core(),
        actor="robert",
        cfg=cfg,
        audit=audit,
        response_text="safe text",
    )
    assert decision.allowed is False
    assert decision.state == "escalate"
    assert "fail_closed:output_gate" in decision.reason

    event = _read_last_event(audit_path)
    assert event["context"]["stage"] == "output_gate"
    assert event["context"]["error_type"] == "RuntimeError"
