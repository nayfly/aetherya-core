from __future__ import annotations

import pytest

from aetherya.pipeline import _aggregator_weights, _mode_thresholds, run_pipeline
from aetherya.risk import RiskDecision


class DummyConstitution:
    def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
        return {"allowed": True, "risk_score": 0, "reason": "ok", "tags": []}


class DummyAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, **kwargs):  # noqa: ANN003
        self.events.append(kwargs)


class DummyCfg:
    class _PG:
        privileged_ops = []

    class _Agg:
        weights = {"procedural_guard": 1, "constitution": 1}
        hard_deny_if = []

    class _Modes:
        def __getitem__(self, _k):  # noqa: ANN001
            class _M:
                class _T:
                    deny_at = 999
                    confirm_at = 999
                    log_only_at = 0

                thresholds = _T()

            return _M()

    procedural_guard = _PG()
    aggregator = _Agg()
    modes = _Modes()
    policy_fingerprint = "sha256:test-policy"


def test_aggregator_weights_non_dict_returns_empty() -> None:
    class Cfg:
        class _Agg:
            weights = "bad"

        aggregator = _Agg()

    assert _aggregator_weights(Cfg()) == {}


def test_mode_thresholds_returns_empty_when_modes_missing() -> None:
    class Cfg:
        modes = None

    assert _mode_thresholds(Cfg(), "operative") == {}


def test_mode_thresholds_returns_empty_when_thresholds_missing() -> None:
    class Cfg:
        class _Modes:
            def __getitem__(self, _k):  # noqa: ANN001
                class _M:
                    thresholds = None

                return _M()

        modes = _Modes()

    assert _mode_thresholds(Cfg(), "operative") == {}


def test_mode_thresholds_parses_dict_thresholds() -> None:
    class Cfg:
        class _Modes:
            def __getitem__(self, _k):  # noqa: ANN001
                class _M:
                    thresholds = {"deny_at": "80", "confirm_at": "50", "log_only_at": "0"}

                return _M()

        modes = _Modes()

    assert _mode_thresholds(Cfg(), "operative") == {
        "deny_at": 80,
        "confirm_at": 50,
        "log_only_at": 0,
    }


def test_pipeline_explainability_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class AggResult:
        decision = RiskDecision.ALLOW
        total_score = 0
        reasons = ["ok"]
        top_signal = None
        breakdown = []

    class Agg:
        def __init__(self, *_a, **_k):  # noqa: ANN001
            pass

        def aggregate(self, _signals, mode: str):  # noqa: ANN001
            return AggResult()

    class BoomExplainability:
        def build(self, **_kwargs):  # noqa: ANN003
            raise RuntimeError("explainability died")

    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)
    monkeypatch.setattr(pipeline, "ExplainabilityEngine", BoomExplainability)

    audit = DummyAudit()
    decision = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=audit
    )
    assert decision.allowed is True
    assert audit.events
    assert "explainability" not in audit.events[0]["context"]


def test_pipeline_audit_context_without_policy_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class AggResult:
        decision = RiskDecision.ALLOW
        total_score = 0
        reasons = ["ok"]
        top_signal = None
        breakdown = []

    class Agg:
        def __init__(self, *_a, **_k):  # noqa: ANN001
            pass

        def aggregate(self, _signals, mode: str):  # noqa: ANN001
            return AggResult()

    class CfgNoFingerprint(DummyCfg):
        policy_fingerprint = None

    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)

    audit = DummyAudit()
    decision = run_pipeline(
        "mode:operative hi",
        DummyConstitution(),
        actor="robert",
        cfg=CfgNoFingerprint(),
        audit=audit,
    )
    assert decision.allowed is True
    assert audit.events
    assert "policy_fingerprint" not in audit.events[0]["context"]
    assert "explainability" in audit.events[0]["context"]
