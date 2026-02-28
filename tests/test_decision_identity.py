from aetherya.actions import POLICY_ABI_VERSION
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
    ]
    return Constitution(principles, audit=audit)


def test_decision_identity_snapshot(tmp_path):
    cfg = load_policy_config("config/policy.yaml")
    audit = AuditLogger(tmp_path / "decisions.jsonl")
    core = make_core(audit)

    decision = run_pipeline("rm -rf /", constitution=core, actor="robert", cfg=cfg)

    snapshot = {
        "allowed": False,
        "violated_principle": "ProceduralSafety",
        "mode": "operative",
        "state": "hard_deny",
        "abi_version": POLICY_ABI_VERSION,
    }

    assert decision.allowed == snapshot["allowed"]
    assert decision.violated_principle == snapshot["violated_principle"]
    assert decision.mode == snapshot["mode"]
    assert decision.state == snapshot["state"]
    assert decision.abi_version == snapshot["abi_version"]
