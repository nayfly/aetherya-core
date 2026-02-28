import pytest

from aetherya.actions import POLICY_ABI_VERSION, ActionRequest
from aetherya.pipeline import run_pipeline
from aetherya.risk import RiskDecision


class DummyCfg:
    class _PG:
        privileged_ops = []
        critical_tags = []

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


class DummyConstitution:
    def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
        return {"allowed": True, "risk_score": 0, "reason": "ok", "tags": []}


def test_pipeline_invalid_actor_fails_closed() -> None:
    d = run_pipeline("run backup", DummyConstitution(), actor=" ", cfg=DummyCfg(), audit=None)
    assert d.allowed is False
    assert "fail_closed:actor" in d.reason
    assert d.state == "escalate"
    assert d.abi_version == POLICY_ABI_VERSION


def test_pipeline_invalid_action_request_shape_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.pipeline as pipeline

    monkeypatch.setattr(pipeline, "parse_user_input", lambda _raw: {"raw_input": "x"})

    d = run_pipeline("run backup", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None)
    assert d.allowed is False
    assert "fail_closed:action_request" in d.reason
    assert d.state == "escalate"


def test_pipeline_decision_dict_exposes_abi_contract(monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(
        pipeline,
        "parse_user_input",
        lambda _raw: ActionRequest(
            raw_input="run backup",
            intent="operate",
            mode_hint="operative",
            tool=None,
            target=None,
            parameters={},
        ),
    )

    d = run_pipeline("run backup", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None)
    payload = d.to_dict()
    assert payload["abi_version"] == POLICY_ABI_VERSION
    assert payload["state"] == "allow"
