from __future__ import annotations

from dataclasses import dataclass

import pytest

from aetherya.pipeline import run_pipeline


@dataclass
class DummyConstitution:
    def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
        return {"risk_score": 0, "reason": "ok", "tags": []}


class DummyAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, actor: str, action: str, decision: dict, context: dict) -> None:
        self.events.append(
            {"actor": actor, "action": action, "decision": decision, "context": context}
        )


# Config mínimo para pipeline (solo lo que se toca)
class DummyCfg:
    def __init__(self) -> None:
        self.procedural_guard = {}  # ProceduralGuard(cfg.procedural_guard)
        self.aggregator = {}  # RiskAggregator(cfg=cfg.aggregator, ...)
        self.modes = {}  # RiskAggregator(..., modes=cfg.modes)
        self.policy_fingerprint = "sha256:test-policy"


def test_pipeline_fail_closed_on_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: str):  # noqa: ANN001
        raise RuntimeError("parse died")

    import aetherya.pipeline as pipeline

    monkeypatch.setattr(pipeline, "parse_user_input", boom)

    cfg = DummyCfg()
    audit = DummyAudit()

    d = run_pipeline("whatever", DummyConstitution(), actor="robert", cfg=cfg, audit=audit)
    assert d.allowed is False
    assert "fail_closed:parse_user_input" in d.reason
    assert audit.events and audit.events[0]["context"]["stage"] == "parse_user_input"


def test_pipeline_fail_closed_on_constitution_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    monkeypatch.setattr(pipeline.ProceduralGuard, "evaluate", lambda self, raw: None)

    class BoomConstitution(DummyConstitution):
        def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
            raise ValueError("constitution died")

    cfg = DummyCfg()
    audit = DummyAudit()

    d = run_pipeline(
        "mode:consultive hello", BoomConstitution(), actor="robert", cfg=cfg, audit=audit
    )
    assert d.allowed is False
    assert "fail_closed:constitution" in d.reason


def test_pipeline_fail_closed_on_aggregate_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    monkeypatch.setattr(pipeline.ProceduralGuard, "evaluate", lambda self, raw: None)

    class BoomAgg:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            pass

        def aggregate(self, signals, mode: str):  # noqa: ANN001
            raise RuntimeError("aggregate died")

    monkeypatch.setattr(pipeline, "RiskAggregator", BoomAgg)

    cfg = DummyCfg()
    audit = DummyAudit()

    d = run_pipeline("mode:operative hi", DummyConstitution(), actor="robert", cfg=cfg, audit=audit)
    assert d.allowed is False
    assert "fail_closed:risk_aggregate" in d.reason


def test_pipeline_fail_closed_on_corrupt_signal_type_in_aggregator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.pipeline as pipeline

    class DummyJailbreakGuard:
        def evaluate(self, text: str):  # noqa: ANN001
            return {
                "risk_score": 95,
                "confidence": 1.0,
                "reason": "prompt injection attempt",
                "tags": ["jailbreak_attempt"],
            }

    monkeypatch.setattr(pipeline, "JailbreakGuard", DummyJailbreakGuard)
    monkeypatch.setattr(pipeline, "RiskSignal", lambda **kwargs: 1)  # noqa: ARG005

    cfg = DummyCfg()
    audit = DummyAudit()

    d = run_pipeline("mode:operative hi", DummyConstitution(), actor="robert", cfg=cfg, audit=audit)
    assert d.allowed is False
    assert "fail_closed:risk_aggregate" in d.reason
    assert d.violated_principle == "FailClosed"
