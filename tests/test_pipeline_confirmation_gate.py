from __future__ import annotations

from pathlib import Path

import yaml

from aetherya.actions import validate_action_request
from aetherya.approval_proof import build_approval_proof
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.parser import parse_user_input
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


def test_pipeline_signed_proof_required_when_enabled(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["confirmation"]["evidence"]["signed_proof"].update(
            {
                "enabled": True,
                "key_env": "AETHERYA_TEST_SIGN_KEY",
                "max_valid_for_sec": 300,
            }
        ),
    )
    cfg = load_policy_config(policy_path)
    decision = run_pipeline(
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a "
        "param.operation=write param.confirm_token=ack:abc12345 "
        "param.confirm_context=approved_by_operator",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False
    assert decision.state == "escalate"
    assert "out-of-band approval proof is missing" in decision.reason


def test_pipeline_signed_proof_allows_when_valid(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    policy_path = write_policy(
        tmp_path,
        lambda data: data["confirmation"]["evidence"]["signed_proof"].update(
            {
                "enabled": True,
                "key_env": "AETHERYA_TEST_SIGN_KEY",
                "max_valid_for_sec": 300,
                "clock_skew_sec": 2,
            }
        ),
    )
    cfg = load_policy_config(policy_path)
    monkeypatch.setenv("AETHERYA_TEST_SIGN_KEY", "integration-sign-key")

    base_input = (
        "mode:operative tool:filesystem target:/tmp param.path=/tmp/a "
        "param.operation=write param.confirm_token=ack:abc12345 "
        "param.confirm_context=approved_by_operator"
    )
    action = validate_action_request(parse_user_input(base_input))
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="integration-sign-key",
        actor="robert",
        action=action,
        ttl_sec=60,
        exclude_params=excluded,
    )

    decision = run_pipeline(
        f"{base_input} param.confirm_proof={proof}",
        constitution=make_core(),
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is True
    assert decision.state == "allow"
