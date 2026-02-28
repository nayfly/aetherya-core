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


def test_pipeline_llm_shadow_attaches_metrics_when_enabled(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["llm_shadow"].update({"enabled": True, "max_tokens": 32}),
    )
    cfg = load_policy_config(policy_path)
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    decision = run_pipeline(
        "help user", constitution=make_core(), actor="robert", cfg=cfg, audit=audit
    )
    assert decision.allowed is True

    event = read_last_event(audit_path)
    llm_shadow = event["context"]["llm_shadow"]
    assert llm_shadow["enabled"] is True
    assert llm_shadow["provider"] == "dry_run"
    assert llm_shadow["dry_run"] is True
    assert llm_shadow["finish_reason"] == "dry_run"
    assert llm_shadow["usage"]["total_tokens"] >= llm_shadow["usage"]["prompt_tokens"]


def test_pipeline_llm_shadow_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import aetherya.pipeline as pipeline

    policy_path = write_policy(
        tmp_path,
        lambda data: data["llm_shadow"].update({"enabled": True}),
    )
    cfg = load_policy_config(policy_path)
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)

    class BoomProvider:
        def __init__(self, seed: str):  # noqa: ARG002
            pass

        def generate(self, request):  # noqa: ANN001
            raise RuntimeError("shadow died")

    monkeypatch.setattr(pipeline, "DryRunLLMProvider", BoomProvider)

    decision = run_pipeline(
        "help user", constitution=make_core(), actor="robert", cfg=cfg, audit=audit
    )
    assert decision.allowed is True

    event = read_last_event(audit_path)
    llm_shadow = event["context"]["llm_shadow"]
    assert llm_shadow["enabled"] is True
    assert llm_shadow["error_type"] == "RuntimeError"
