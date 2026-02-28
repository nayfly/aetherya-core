from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.pipeline import run_pipeline


def make_core() -> Constitution:
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


def write_policy(tmp_path: Path, mutate) -> Path:  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def read_last_event(path: Path) -> dict:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1])


def test_pipeline_policy_adapter_shadow_attaches_metrics_when_enabled(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["policy_adapter_shadow"].update({"enabled": True, "max_signals": 2}),
    )
    cfg = load_policy_config(policy_path)
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    decision = run_pipeline(
        "Need privileged root access for maintenance.",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
        audit=audit,
    )
    assert decision.allowed is True

    event = read_last_event(audit_path)
    shadow = event["context"]["policy_adapter_shadow"]
    assert shadow["enabled"] is True
    assert shadow["adapter"] == "dry_run_policy_adapter"
    assert shadow["dry_run"] is True
    assert shadow["max_signals"] == 2
    assert isinstance(shadow["projected_total_risk"], int)


def test_pipeline_policy_adapter_shadow_does_not_change_decision(tmp_path: Path) -> None:
    base_cfg = load_policy_config("config/policy.yaml")
    shadow_policy_path = write_policy(
        tmp_path,
        lambda data: data["policy_adapter_shadow"].update({"enabled": True}),
    )
    shadow_cfg = load_policy_config(shadow_policy_path)
    core = make_core()

    raw_input = "Need privileged root access for maintenance."
    base = run_pipeline(raw_input, constitution=core, actor="robert", cfg=base_cfg)
    with_shadow = run_pipeline(raw_input, constitution=core, actor="robert", cfg=shadow_cfg)

    assert with_shadow.allowed == base.allowed
    assert with_shadow.state == base.state
    assert with_shadow.risk_score == base.risk_score
    assert with_shadow.violated_principle == base.violated_principle


def test_pipeline_policy_adapter_shadow_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import aetherya.pipeline as pipeline

    policy_path = write_policy(
        tmp_path,
        lambda data: data["policy_adapter_shadow"].update({"enabled": True}),
    )
    cfg = load_policy_config(policy_path)
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    class BoomAdapter:
        adapter_name = "boom"

        def __init__(self, seed: str):  # noqa: ARG002
            pass

        def suggest(self, request):  # noqa: ANN001
            raise RuntimeError("adapter died")

    monkeypatch.setattr(pipeline, "DryRunPolicyDecisionAdapter", BoomAdapter)

    decision = run_pipeline(
        "help user", constitution=make_core(), actor="robert", cfg=cfg, audit=audit
    )
    assert decision.allowed is True

    event = read_last_event(audit_path)
    shadow = event["context"]["policy_adapter_shadow"]
    assert shadow["enabled"] is True
    assert shadow["error_type"] == "RuntimeError"


def test_pipeline_policy_adapter_shadow_invalid_signal_item_is_swallowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import aetherya.pipeline as pipeline

    policy_path = write_policy(
        tmp_path,
        lambda data: data["policy_adapter_shadow"].update({"enabled": True}),
    )
    cfg = load_policy_config(policy_path)
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    class BadResponse:
        adapter = "bad"
        request_id = "bad-1"
        dry_run = True
        metadata = {}
        signals = [1]
        decision_candidates = []

        def validate(self) -> None:
            return None

    class BadAdapter:
        adapter_name = "bad"

        def __init__(self, seed: str):  # noqa: ARG002
            pass

        def suggest(self, request):  # noqa: ANN001
            return BadResponse()

    monkeypatch.setattr(pipeline, "DryRunPolicyDecisionAdapter", BadAdapter)

    decision = run_pipeline(
        "help user", constitution=make_core(), actor="robert", cfg=cfg, audit=audit
    )
    assert decision.allowed is True

    event = read_last_event(audit_path)
    shadow = event["context"]["policy_adapter_shadow"]
    assert shadow["enabled"] is True
    assert shadow["error_type"] in {"AttributeError", "TypeError"}
