from __future__ import annotations

from pathlib import Path

import yaml

from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.pipeline import run_pipeline


def make_core() -> Constitution:
    return Constitution(
        [
            Principle(
                "Non-harm",
                "Do not cause harm",
                priority=1,
                keywords=["harm", "kill", "attack"],
                risk=90,
            )
        ]
    )


def write_policy(tmp_path, mutate):  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def test_pipeline_operate_without_tool_escalates() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline("run cleanup now", constitution=make_core(), actor="robert", cfg=cfg)
    assert decision.allowed is False
    assert decision.state == "escalate"
    assert decision.violated_principle == "ExecutionSafety"


def test_pipeline_tool_not_allowed_hard_denies() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:docker target:local param.command=ps",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "hard_deny"
    assert decision.violated_principle == "ExecutionSafety"


def test_pipeline_valid_structured_tool_allows_in_operative() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:shell target:local param.command=ls",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is True
    assert decision.state == "allow"


def test_pipeline_execution_gate_requires_target_when_configured(tmp_path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["execution_gate"].update({"require_target_for_operate": True}),
    )
    cfg = load_policy_config(policy_path)

    decision = run_pipeline(
        "mode:operative tool:shell param.command=ls",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state in {"escalate", "deny"}
    assert decision.violated_principle == "ExecutionSafety"
