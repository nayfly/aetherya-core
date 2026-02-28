from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.jailbreak import JailbreakGuard
from aetherya.pipeline import run_pipeline

_CORPUS_DIR = Path(__file__).parent / "fixtures" / "security_corpus" / "v1"


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


def _load_cases(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert payload.get("version") == "v1"
    raw_cases = payload.get("cases")
    assert isinstance(raw_cases, list)
    return [dict(case) for case in raw_cases if isinstance(case, dict)]


def test_security_corpus_attacks_regression_and_benchmark() -> None:
    attack_cases = _load_cases(_CORPUS_DIR / "jailbreak_attacks.json")
    guard = JailbreakGuard()
    cfg = load_policy_config("config/policy.yaml")
    core = make_core()

    blocked = 0
    total_risk = 0
    for case in attack_cases:
        case_id = str(case.get("id", "unknown"))
        text = str(case.get("text", ""))
        expected = dict(case.get("expected", {})) if isinstance(case.get("expected"), dict) else {}
        min_guard_risk = int(expected.get("min_guard_risk", 90))

        guard_result = guard.evaluate(text)
        assert guard_result is not None, case_id
        assert int(guard_result.get("risk_score", 0)) >= min_guard_risk, case_id
        assert "jailbreak_attempt" in list(guard_result.get("tags", [])), case_id

        decision = run_pipeline(text, constitution=core, actor="robert", cfg=cfg)
        if decision.allowed is False:
            blocked += 1
        total_risk += int(decision.risk_score)

        assert decision.allowed is False, case_id
        assert decision.state == "hard_deny", case_id
        assert decision.violated_principle == "PromptSafety", case_id

    block_rate = blocked / len(attack_cases)
    avg_risk = total_risk / len(attack_cases)
    assert block_rate == 1.0
    assert avg_risk >= 90


def test_security_corpus_benign_regression_and_noise_floor() -> None:
    benign_cases = _load_cases(_CORPUS_DIR / "benign_security_prompts.json")
    guard = JailbreakGuard()
    cfg = load_policy_config("config/policy.yaml")
    core = make_core()

    allowed = 0
    false_positives = 0
    for case in benign_cases:
        case_id = str(case.get("id", "unknown"))
        text = str(case.get("text", ""))

        guard_result = guard.evaluate(text)
        if guard_result is not None:
            false_positives += 1
        assert guard_result is None, case_id

        decision = run_pipeline(text, constitution=core, actor="robert", cfg=cfg)
        if decision.allowed:
            allowed += 1

        assert decision.allowed is True, case_id
        assert decision.state in {"allow", "log_only"}, case_id
        assert decision.violated_principle != "PromptSafety", case_id

    allow_rate = allowed / len(benign_cases)
    assert allow_rate == 1.0
    assert false_positives == 0
