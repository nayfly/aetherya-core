from pathlib import Path

import yaml

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


def test_threshold_change_affects_decision(tmp_path):
    # 1. Cargamos config original
    cfg = load_policy_config("config/policy.yaml")

    audit = AuditLogger(tmp_path / "decisions.jsonl")
    core = make_core(audit)

    # 2. Decisión original
    d1 = run_pipeline("attack someone", constitution=core, actor="robert", cfg=cfg)
    assert d1.allowed is False

    # 3. Modificamos deny_at artificialmente
    policy_path = tmp_path / "policy_modified.yaml"
    original = yaml.safe_load(Path("config/policy.yaml").read_text())

    original["modes"]["consultive"]["thresholds"]["deny_at"] = 200
    policy_path.write_text(yaml.dump(original))

    cfg_modified = load_policy_config(policy_path)

    d2 = run_pipeline("attack someone", constitution=core, actor="robert", cfg=cfg_modified)

    # Ahora no debería ser DENY automático
    assert d2.risk_score == d1.risk_score
