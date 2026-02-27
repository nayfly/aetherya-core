import pytest

from aetherya.pipeline import run_pipeline


class DummyCfg:  # minimal cfg stub compatible con pipeline
    class _PG:
        privileged_ops: list[str] = []
        critical_tags: list[str] = []

    class _Agg:
        weights: dict[str, int] = {}
        hard_deny_if: list[str] = []

    procedural_guard = _PG()
    aggregator = _Agg()
    modes = {}  # si tu RiskAggregator espera dict, mejor dict


class DummyAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, **kwargs):  # noqa: ANN003
        self.events.append(kwargs)


class DummyConstitution:
    def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
        return {"allowed": True, "risk_score": 0, "reason": "ok", "tags": []}


def test_pipeline_invalid_mode_hint_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Forzamos parse_user_input a devolver un action con mode_hint inválido
    import aetherya.pipeline as pipeline

    class A:  # dummy action
        mode_hint = "NOT_A_MODE"

    monkeypatch.setattr(pipeline, "parse_user_input", lambda _: A())

    d = run_pipeline("whatever", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None)
    assert d.allowed is False
    assert "fail_closed:mode" in d.reason
    assert d.violated_principle == "FailClosed"


def test_pipeline_procedural_guard_raises_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class BoomGuard:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _raw: str):  # noqa: ANN001
            raise ValueError("guard died")

    monkeypatch.setattr(pipeline, "ProceduralGuard", BoomGuard)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    assert d.allowed is False
    assert "fail_closed:procedural_guard" in d.reason
    assert d.violated_principle == "FailClosed"


def test_pipeline_audit_failure_does_not_change_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    # Audit no debe tumbar el pipeline; se ignora (pero decisión se mantiene)
    audit = DummyAudit()

    def boom_log(**_kwargs):  # noqa: ANN001
        raise RuntimeError("audit died")

    audit.log = boom_log  # type: ignore[method-assign]

    d = run_pipeline(
        "mode:consultive hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=audit
    )
    # En consultivo, allowed depende de tu pipeline; normalmente LOG_ONLY -> allowed False o True según Decision
    # Aquí comprobamos que NO sea fail_closed por audit.
    assert "fail_closed:audit" not in d.reason


def test_pipeline_aggregate_returns_unknown_decision_maps_to_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.pipeline as pipeline

    # Aisla procedural guard para que no explote por cfg dummy
    class NoopGuard:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _raw: str):  # noqa: ANN001
            return None

    monkeypatch.setattr(pipeline, "ProceduralGuard", NoopGuard)

    class AggResult:
        decision = "SOMETHING_NEW"
        total_score = 0
        reasons = ["ok"]
        top_signal = None
        breakdown = []

    class Agg:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def aggregate(self, _signals, mode: str):  # noqa: ANN001
            return AggResult()

    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    assert d.allowed is True
