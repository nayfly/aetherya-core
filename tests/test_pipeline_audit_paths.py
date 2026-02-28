import pytest

from aetherya.pipeline import run_pipeline
from aetherya.risk import RiskDecision


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


class DummyConstitution:
    def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
        return {"allowed": True, "risk_score": 0, "reason": "ok", "tags": []}


class AuditOK:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, **kwargs):  # noqa: ANN003
        self.events.append(kwargs)


class AuditBoom:
    def log(self, **_kwargs):  # noqa: ANN003
        raise RuntimeError("audit died")


class AuditSetterBoom(AuditOK):
    def set_policy_fingerprint(self, _value: str) -> None:
        raise RuntimeError("setter died")


def test_pipeline_audit_log_is_called_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
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

    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)

    audit = AuditOK()
    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=audit
    )
    assert d.allowed is True
    assert len(audit.events) == 1  # cubre 185-194
    assert "explainability" in audit.events[0]["context"]
    assert audit.events[0]["context"]["explainability"]["summary"]["state"] == "allow"
    assert audit.events[0]["context"]["policy_fingerprint"] == "sha256:test-policy"


def test_pipeline_audit_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
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

    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=AuditBoom()
    )
    assert d.allowed is True
    assert "fail_closed:audit" not in d.reason  # cubre 195-196


def test_pipeline_policy_fingerprint_setter_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)

    audit = AuditSetterBoom()
    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=audit
    )
    assert d.allowed is True
    assert len(audit.events) == 1
