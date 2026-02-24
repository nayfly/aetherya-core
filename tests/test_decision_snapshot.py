from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.pipeline import run_pipeline
from utils import assert_matches_snapshot


def make_core(audit):
    principles = [
        Principle(
            "Non-harm",
            "Do not cause harm",
            priority=1,
            keywords=["harm", "kill", "attack"],
            risk=90,
        ),
    ]
    return Constitution(principles, audit=audit)


def test_rm_rf_snapshot(tmp_path):
    cfg = load_policy_config("config/policy.yaml")
    audit = AuditLogger(tmp_path / "decisions.jsonl")
    core = make_core(audit)

    decision = run_pipeline("rm -rf /", constitution=core, actor="robert", cfg=cfg)

    assert_matches_snapshot("rm_rf_decision", decision.to_dict())
