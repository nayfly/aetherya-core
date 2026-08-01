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


def test_pipeline_audit_context_includes_constitution_semantic_score(
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

    class SemanticConstitution:
        def evaluate(self, action, actor: str, context: dict):  # noqa: ANN001
            return {
                "allowed": True,
                "risk_score": 0,
                "reason": "ok",
                "tags": [],
                "semantic_score": 0.42,
            }

    audit = AuditOK()
    d = run_pipeline(
        "mode:operative hi", SemanticConstitution(), actor="robert", cfg=DummyCfg(), audit=audit
    )
    assert d.allowed is True
    assert audit.events[0]["context"]["constitution"] == {"semantic_score": 0.42}


def test_pipeline_audit_context_omits_constitution_block_without_semantic_score(
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

    audit = AuditOK()
    d = run_pipeline(
        "mode:operative hi", DummyConstitution(), actor="robert", cfg=DummyCfg(), audit=audit
    )
    assert d.allowed is True
    assert "constitution" not in audit.events[0]["context"]


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


# ---------------------------------------------------------------------------
# What the trail has to carry for phase-1 vocabulary analysis
# ---------------------------------------------------------------------------


def test_the_audit_records_the_structured_action(tmp_path) -> None:  # noqa: ANN001
    """
    Regression: `context.action` was never written, so every real decision had
    `tool: null` and recovering an agent's vocabulary meant regexing prose.
    Phase 1 exists to tell you what your agent actually calls, and that needs
    structure. The console test passed only because it seeded the field by hand.
    """
    import json
    from pathlib import Path

    from aetherya.actions import ActionRequest
    from aetherya.audit import AuditLogger
    from aetherya.config import load_policy_config
    from aetherya.constitution import Constitution
    from aetherya.pipeline import run_pipeline_structured

    path = tmp_path / "decisions.jsonl"
    run_pipeline_structured(
        ActionRequest(
            raw_input="exec ls -la",
            intent="operate",
            tool="shell",
            target="/srv/app",
            parameters={"command": "ls -la", "operation": "read"},
        ),
        constitution=Constitution([], use_semantic=False),
        actor="robert",
        cfg=load_policy_config(Path("config/policy.yaml")),
        audit=AuditLogger(str(path)),
    )

    recorded = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])["context"]["action"]
    assert recorded["tool"] == "shell"
    assert recorded["intent"] == "operate"
    assert recorded["target"] == "/srv/app"
    assert recorded["operation"] == "read"
    assert recorded["parameter_names"] == ["command", "operation"]


def test_the_audit_records_parameter_names_but_never_their_values(tmp_path) -> None:  # noqa: ANN001
    """
    A confirmed action carries `confirm_proof`, a single-use credential. The
    trail is exported, mirrored and archived — anything written there cannot be
    taken back out.
    """
    import json
    from pathlib import Path

    from aetherya.actions import ActionRequest
    from aetherya.audit import AuditLogger
    from aetherya.config import load_policy_config
    from aetherya.constitution import Constitution
    from aetherya.pipeline import run_pipeline_structured

    path = tmp_path / "decisions.jsonl"
    run_pipeline_structured(
        ActionRequest(
            raw_input="write config",
            intent="operate",
            tool="filesystem",
            parameters={"operation": "write", "confirm_proof": "ap1.k1.SECRET-PROOF-VALUE"},
        ),
        constitution=Constitution([], use_semantic=False),
        actor="robert",
        cfg=load_policy_config(Path("config/policy.yaml")),
        audit=AuditLogger(str(path)),
    )

    line = path.read_text(encoding="utf-8").splitlines()[-1]
    assert "SECRET-PROOF-VALUE" not in line
    assert "confirm_proof" in json.loads(line)["context"]["action"]["parameter_names"]
