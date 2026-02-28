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


def test_pipeline_capability_blocks_unknown_actor() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:shell target:local param.command=ls",
        constitution=make_core(),
        actor="intruder",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state in {"deny", "hard_deny"}
    assert decision.violated_principle == "CapabilitySafety"


def test_pipeline_capability_blocks_disallowed_operation() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=delete",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state in {"deny", "hard_deny"}
    assert decision.violated_principle == "CapabilitySafety"


def test_pipeline_capability_allows_authorized_operation() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=read",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is True
    assert decision.state == "allow"


def test_pipeline_capability_tool_denied_triggers_hard_deny_rule(tmp_path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["capability_matrix"]["roles"]["operator"].update(
            {"tools": ["filesystem"]}
        ),
    )
    cfg = load_policy_config(policy_path)
    decision = run_pipeline(
        "mode:operative tool:shell target:local param.command=ls",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "hard_deny"
    assert decision.violated_principle == "CapabilitySafety"


def test_pipeline_capability_known_actor_without_caps_denies(tmp_path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["capability_matrix"]["actors"]["robert"].update(
            {"roles": [], "tools": [], "operations": []}
        ),
    )
    cfg = load_policy_config(policy_path)
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=read",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "hard_deny"
    assert decision.violated_principle == "CapabilitySafety"
