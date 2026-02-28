import pytest

from aetherya.actions import ActionRequest
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

    monkeypatch.setattr(
        pipeline,
        "parse_user_input",
        lambda _: ActionRequest(
            raw_input="whatever",
            intent="ask",
            mode_hint="NOT_A_MODE",
            tool=None,
            target=None,
            parameters={},
        ),
    )

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


def test_pipeline_aggregate_returns_unknown_decision_fails_closed_to_escalate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.pipeline as pipeline

    class NoopGuard:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _raw: str):  # noqa: ANN001
            return None

    monkeypatch.setattr(pipeline, "ProceduralGuard", NoopGuard)

    class AggResult:
        decision = "SOMETHING_NEW"  # unknown
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

    monkeypatch.setattr(
        pipeline,
        "parse_user_input",
        lambda _raw: ActionRequest(
            raw_input="mode:operative hi",
            intent="operate",
            mode_hint="operative",
            tool=None,
            target=None,
            parameters={},
        ),
    )

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )

    assert d.allowed is False
    assert d.reason.startswith("escalate:")


def test_pipeline_execution_gate_raises_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class BoomGate:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _action):  # noqa: ANN001
            raise ValueError("gate died")

    monkeypatch.setattr(pipeline, "ExecutionGate", BoomGate)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    assert d.allowed is False
    assert "fail_closed:execution_gate" in d.reason
    assert d.violated_principle == "FailClosed"


def test_pipeline_capability_gate_raises_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class NoopGate:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _action):  # noqa: ANN001
            return None

    class BoomCapabilityGate:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, *, actor: str, action):  # noqa: ANN001
            raise ValueError("capability died")

    monkeypatch.setattr(pipeline, "ExecutionGate", NoopGate)
    monkeypatch.setattr(pipeline, "CapabilityGate", BoomCapabilityGate)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    assert d.allowed is False
    assert "fail_closed:capability_gate" in d.reason
    assert d.violated_principle == "FailClosed"


def test_pipeline_jailbreak_guard_raises_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class NoopGate:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _action):  # noqa: ANN001
            return None

    class BoomJailbreakGuard:
        def evaluate(self, _raw: str):  # noqa: ANN001
            raise ValueError("jb died")

    monkeypatch.setattr(pipeline, "ExecutionGate", NoopGate)
    monkeypatch.setattr(pipeline, "JailbreakGuard", BoomJailbreakGuard)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    assert d.allowed is False
    assert "fail_closed:jailbreak_guard" in d.reason
    assert d.violated_principle == "FailClosed"


def test_pipeline_decision_validate_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class NoopGate:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _action):  # noqa: ANN001
            return None

    class NoopGuard:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def evaluate(self, _raw: str):  # noqa: ANN001
            return None

    class AggResult:
        decision = "allow"
        total_score = 0
        reasons = ["ok"]
        top_signal = None
        breakdown = []

    class Agg:
        def __init__(self, *_args, **_kwargs):  # noqa: ANN001
            pass

        def aggregate(self, _signals, mode: str):  # noqa: ANN001
            return AggResult()

    def boom_validate(_self):  # noqa: ANN001
        raise ValueError("x")

    monkeypatch.setattr(pipeline, "ExecutionGate", NoopGate)
    monkeypatch.setattr(pipeline, "ProceduralGuard", NoopGuard)
    monkeypatch.setattr(pipeline, "RiskAggregator", Agg)
    monkeypatch.setattr(pipeline.Decision, "validate", boom_validate)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    assert d.allowed is False
    assert "fail_closed:decision_contract" in d.reason
