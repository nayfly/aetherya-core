import pytest

from aetherya.pipeline import run_pipeline


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


class DummyConstitution:
    def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
        return {"allowed": True, "risk_score": 0, "reason": "ok", "tags": []}


def test_pipeline_safe_casts_cover_safe_int_and_float(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.pipeline as pipeline

    class Guard:
        def __init__(self, *_a, **_k):  # noqa: ANN001
            pass

        def evaluate(self, _raw: str):  # noqa: ANN001
            # Esto fuerza los except de _safe_int y _safe_float
            return {"risk_score": "nope", "confidence": "nope", "reason": "x", "tags": []}

    monkeypatch.setattr(pipeline, "ProceduralGuard", Guard)

    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=None
    )
    # No debe fail-closed: safe-cast lo rescata
    assert "fail_closed" not in d.reason
