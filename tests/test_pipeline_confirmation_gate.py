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
                "Caution",
                "Need confirmation for sensitive requests",
                priority=1,
                keywords=["sensitive"],
                risk=55,
            )
        ]
    )


def write_policy(tmp_path, mutate):  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def test_pipeline_require_confirm_without_evidence_stays_escalate() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a "
        "param.operation=read sensitive",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "escalate"


def test_pipeline_allow_path_escalates_when_confirmation_is_missing() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "escalate"
    assert "strong confirmation evidence is missing" in decision.reason
    assert decision.violated_principle == "ConfirmationSafety"


def test_pipeline_require_confirm_with_strong_confirmation_allows() -> None:
    cfg = load_policy_config("config/policy.yaml")
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a "
        "param.operation=read param.confirm_token=ack:abc12345 "
        "param.confirm_context=approved_for_sensitive_action sensitive",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is True
    assert decision.state == "allow"


def test_pipeline_confirmed_without_override_stays_escalate(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["confirmation"].update({"on_confirmed": ""}),
    )
    cfg = load_policy_config(policy_path)
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a "
        "param.operation=read param.confirm_token=ack:abc12345 "
        "param.confirm_context=approved_for_sensitive_action sensitive",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "escalate"
    assert "strong confirmation validated" not in decision.reason


def test_pipeline_invalid_confirmation_pattern_fails_closed(tmp_path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["confirmation"]["evidence"].update({"token_pattern": "("}),
    )
    cfg = load_policy_config(policy_path)
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a "
        "param.operation=read param.confirm_token=ack:abc12345 "
        "param.confirm_context=approved_for_sensitive_action sensitive",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert "fail_closed:confirmation_gate" in decision.reason
