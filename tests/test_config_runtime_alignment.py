from __future__ import annotations

from pathlib import Path

import yaml

from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.pipeline import run_pipeline


def make_core() -> Constitution:
    principles = [
        Principle(
            "Non-harm",
            "Do not cause harm",
            priority=1,
            keywords=["harm", "kill", "attack"],
            risk=90,
        ),
    ]
    return Constitution(principles)


def write_policy(tmp_path, mutate):  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def test_weights_change_runtime_score(tmp_path) -> None:
    core = make_core()
    base_cfg = load_policy_config("config/policy.yaml")
    base = run_pipeline("sudo apt remove docker", constitution=core, actor="robert", cfg=base_cfg)

    weighted_path = write_policy(
        tmp_path,
        lambda data: data["aggregator"]["weights"].update({"procedural_guard": 2.0}),
    )
    weighted_cfg = load_policy_config(weighted_path)
    weighted = run_pipeline(
        "sudo apt remove docker", constitution=core, actor="robert", cfg=weighted_cfg
    )

    assert weighted.risk_score > base.risk_score


def test_hard_deny_if_tag_rule_changes_runtime_state(tmp_path) -> None:
    core = make_core()
    hard_path = write_policy(
        tmp_path,
        lambda data: data["aggregator"].update({"hard_deny_if": ["tag:system_change"]}),
    )
    cfg = load_policy_config(hard_path)

    decision = run_pipeline("sudo apt remove docker", constitution=core, actor="robert", cfg=cfg)
    assert decision.state == "hard_deny"
    assert decision.allowed is False


def test_critical_tags_drive_procedural_guard(tmp_path) -> None:
    core = make_core()
    no_critical_path = write_policy(
        tmp_path,
        lambda data: (
            data["procedural_guard"].update({"critical_tags": []}),
            data["execution_gate"].update({"enabled": False}),
        ),
    )
    cfg = load_policy_config(no_critical_path)

    decision = run_pipeline("rm -rf /", constitution=core, actor="robert", cfg=cfg)
    assert decision.violated_principle != "ProceduralSafety"
    assert decision.risk_score == 0
    assert decision.allowed is True


def test_mode_default_state_changes_zero_risk_decision(tmp_path) -> None:
    core = make_core()
    allow_default_path = write_policy(
        tmp_path,
        lambda data: data["modes"]["consultive"].update({"default_state": "allow"}),
    )
    cfg = load_policy_config(allow_default_path)

    decision = run_pipeline("help user", constitution=core, actor="robert", cfg=cfg)
    assert decision.state == "allow"
    assert decision.allowed is True


def test_log_only_threshold_changes_low_risk_behavior(tmp_path) -> None:
    core = make_core()

    tuned_path = write_policy(
        tmp_path,
        lambda data: data["modes"]["operative"]["thresholds"].update({"log_only_at": 30}),
    )
    cfg = load_policy_config(tuned_path)

    decision = run_pipeline(
        "mode:operative tool:shell target:local param.command=sudo_apt_remove_docker "
        "sudo apt remove docker",
        constitution=core,
        actor="robert",
        cfg=cfg,
    )
    assert decision.state == "allow"
    assert decision.allowed is True
