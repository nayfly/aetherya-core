import json

from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.pipeline import run_pipeline


def make_core(audit):
    principles = [
        Principle(
            "Non-harm",
            "Do not cause harm",
            priority=1,
            keywords=["harm", "kill", "attack"],
            risk=90,
        ),
        Principle(
            "Deception",
            "Avoid manipulation",
            priority=2,
            keywords=["lie", "deceive"],
            risk=80,
        ),
    ]
    return Constitution(principles, audit=audit)


def test_help_user_is_allowed_consultive(tmp_path):
    cfg = load_policy_config("config/policy.yaml")
    audit = AuditLogger(tmp_path / "decisions.jsonl")
    core = make_core(audit)

    decision = run_pipeline("help user", constitution=core, actor="robert", cfg=cfg)
    assert decision.allowed is True
    assert decision.mode == "consultive"
    assert decision.risk_score == 0


def test_rm_rf_root_is_denied(tmp_path):
    cfg = load_policy_config("config/policy.yaml")
    audit = AuditLogger(tmp_path / "decisions.jsonl")
    core = make_core(audit)

    decision = run_pipeline("rm -rf /", constitution=core, actor="robert", cfg=cfg)
    assert decision.allowed is False
    assert decision.violated_principle == "ProceduralSafety"
    assert decision.risk_score >= 90


def test_privileged_pkg_removal_is_not_auto_allowed(tmp_path):
    cfg = load_policy_config("config/policy.yaml")
    audit = AuditLogger(tmp_path / "decisions.jsonl")
    core = make_core(audit)

    decision = run_pipeline(
        "mode:operative tool:shell target:local param.command=sudo_apt_remove_docker "
        "sudo apt remove docker",
        constitution=core,
        actor="robert",
        cfg=cfg,
    )
    assert decision.allowed is False  # no ejecución automática
    assert decision.violated_principle == "ProceduralSafety"


def test_policy_fingerprint_is_attached_to_audit_events(tmp_path):
    cfg = load_policy_config("config/policy.yaml")
    audit_path = tmp_path / "decisions.jsonl"
    audit = AuditLogger(audit_path)
    core = make_core(audit)

    run_pipeline("help user", constitution=core, actor="robert", cfg=cfg)

    events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert events
    for event in events:
        assert event["policy_fingerprint"] == cfg.policy_fingerprint
        assert event["context"]["policy_fingerprint"] == cfg.policy_fingerprint
