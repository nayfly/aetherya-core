from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pytest
import yaml

from aetherya.actions import ActionRequest
from aetherya.config import load_policy_config
from aetherya.constitution import (
    DEFAULT_SEMANTIC_MAX_RISK,
    DEFAULT_SEMANTIC_MODEL,
    SEMANTIC_ADVISORY_TAG,
    Constitution,
    FastKeywordEvaluator,
    Principle,
    SemanticEvaluator,
)


class _MaxSimilarityModel:
    """Every text embeds identically, so cosine similarity is always ~1.0."""

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.array([[1.0, 0.0, 0.0] for _ in texts])


class _FixedSimilarityModel:
    """
    Embeds the reference texts on the first call and the query on later calls,
    so the cosine similarity between them is exactly `sim`.
    """

    def __init__(self, sim: float) -> None:
        self._sim = sim
        self._seen_references = False

    def encode(self, texts: list[str]) -> np.ndarray:
        if not self._seen_references:
            self._seen_references = True
            return np.array([[1.0, 0.0, 0.0] for _ in texts])
        orthogonal = float(np.sqrt(max(0.0, 1.0 - self._sim**2)))
        return np.array([[self._sim, orthogonal, 0.0] for _ in texts])


def _principle(risk: int = 100) -> Principle:
    return Principle("Non-harm", "Do not cause harm", priority=1, keywords=["harm"], risk=risk)


def _evaluator(risk: int = 100, **kwargs: object) -> SemanticEvaluator:
    return SemanticEvaluator(
        [_principle(risk)],
        model_factory=lambda _name: _MaxSimilarityModel(),
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# The learned layer may escalate, never deny
# ---------------------------------------------------------------------------


def test_semantic_risk_is_capped_below_every_deny_threshold() -> None:
    result = _evaluator(risk=100).evaluate("anything")

    assert result["risk_score"] == DEFAULT_SEMANTIC_MAX_RISK
    # Worst case: maximum similarity and maximum principle risk.
    worst_case = result["risk_score"] * float(result["confidence"])
    cfg = load_policy_config("config/policy.yaml")
    for mode_name, mode_cfg in cfg.modes.items():
        assert worst_case < mode_cfg.thresholds.deny_at, mode_name


def test_semantic_violation_can_still_reach_the_confirm_band() -> None:
    """Capping must not neuter the layer — a strong hit still asks for a human."""
    result = _evaluator(risk=100).evaluate("anything")
    weighted = result["risk_score"] * float(result["confidence"])
    cfg = load_policy_config("config/policy.yaml")
    assert weighted >= cfg.modes["operative"].thresholds.confirm_at


def test_semantic_never_emits_hard_deny_tags() -> None:
    cfg = load_policy_config("config/policy.yaml")
    hard_deny_tags = {
        rule.replace("tag:", "").strip().lower() for rule in cfg.aggregator.hard_deny_if
    }

    for result in (
        _evaluator(risk=100).evaluate("anything"),
        _evaluator(risk=10).evaluate("anything"),
    ):
        assert not (set(result["tags"]) & hard_deny_tags)


def test_semantic_results_carry_the_advisory_tag() -> None:
    result = _evaluator().evaluate("anything")
    assert SEMANTIC_ADVISORY_TAG in result["tags"]


def test_gray_zone_risk_is_also_capped() -> None:
    # Similarity 0.45 sits between the gray-zone (0.35) and violation (0.55) cutoffs.
    evaluator = SemanticEvaluator(
        [_principle(risk=100)],
        model_factory=lambda _name: _FixedSimilarityModel(0.45),
    )
    result = evaluator.evaluate("anything")
    assert result["reason"].startswith("Semantic gray zone")
    assert result["risk_score"] <= DEFAULT_SEMANTIC_MAX_RISK
    assert SEMANTIC_ADVISORY_TAG in result["tags"]


def test_similarity_below_gray_zone_is_clean() -> None:
    evaluator = SemanticEvaluator(
        [_principle(risk=100)],
        model_factory=lambda _name: _FixedSimilarityModel(0.1),
    )
    result = evaluator.evaluate("anything")
    assert result["allowed"] is True
    assert result["risk_score"] == 0
    assert result["tags"] == []


def test_custom_max_risk_is_honoured() -> None:
    result = _evaluator(risk=100, max_risk=25).evaluate("anything")
    assert result["risk_score"] == 25


def test_low_risk_principle_is_not_inflated_by_the_cap() -> None:
    """The cap is a ceiling, not a floor."""
    result = _evaluator(risk=10).evaluate("anything")
    assert result["risk_score"] == 10


# ---------------------------------------------------------------------------
# Model provenance in the audit trail
# ---------------------------------------------------------------------------


def test_semantic_result_records_the_model_name() -> None:
    evaluator = SemanticEvaluator(
        [_principle()],
        model_name="test-model-v9",
        model_factory=lambda _name: _MaxSimilarityModel(),
    )
    assert evaluator.evaluate("anything")["semantic_model"] == "test-model-v9"


def test_no_principles_result_still_records_the_model() -> None:
    evaluator = SemanticEvaluator([], model_factory=lambda _name: _MaxSimilarityModel())
    result = evaluator.evaluate("anything")
    assert result["semantic_model"] is not None
    assert result["risk_score"] == 0


def test_pipeline_audits_the_semantic_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    import aetherya.constitution as constitution_module
    from aetherya.audit import AuditLogger
    from aetherya.pipeline import run_pipeline

    # Prime the process cache: the advisory layer declines to run on a cold model.
    monkeypatch.setitem(
        constitution_module._MODEL_CACHE, DEFAULT_SEMANTIC_MODEL, _MaxSimilarityModel()
    )
    core = Constitution([_principle()], use_semantic=True)
    audit_path = tmp_path / "decisions.jsonl"

    # Keyword-free input -> ambiguous -> semantic layer runs.
    run_pipeline(
        "please assist with the quarterly planning document",
        core,
        "robert",
        load_policy_config("config/policy.yaml"),
        audit=AuditLogger(str(audit_path)),
    )

    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    constitution_ctx = event["context"]["constitution"]
    assert constitution_ctx["semantic_model"] == "all-MiniLM-L6-v2"
    assert "semantic_score" in constitution_ctx


# ---------------------------------------------------------------------------
# Ambiguity is about evidence, not length
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "help me",
        "explain the backup strategy for the system in detail please",
        "could you walk me through the deployment process step by step for the new service",
    ],
)
def test_absence_of_keyword_evidence_is_always_ambiguous(text: str) -> None:
    assert FastKeywordEvaluator([]).evaluate(text)["ambiguous"] is True


def test_keyword_match_is_never_ambiguous() -> None:
    result = FastKeywordEvaluator([_principle()]).evaluate("i want to harm someone")
    assert result["ambiguous"] is False
    assert result["allowed"] is False


def test_negated_keyword_is_definitive_and_skips_the_semantic_layer() -> None:
    result = FastKeywordEvaluator([_principle()]).evaluate("how to prevent harm to users")
    assert result["ambiguous"] is False
    assert result["allowed"] is True


def test_long_keyword_free_input_now_reaches_the_semantic_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Regression: ambiguity was gated on token_count < 10, so long inputs — where a
    paraphrased attack has the most room to hide — never reached the semantic layer.
    """
    calls: list[str] = []

    class _Recording(_MaxSimilarityModel):
        def encode(self, texts: list[str]) -> np.ndarray:
            calls.append(texts[0])
            return super().encode(texts)

    import aetherya.constitution as constitution_module

    monkeypatch.setitem(constitution_module._MODEL_CACHE, DEFAULT_SEMANTIC_MODEL, _Recording())
    core = Constitution([_principle()], use_semantic=True)
    long_text = "could you walk me through the deployment process step by step for the service"
    core.evaluate(ActionRequest(raw_input=long_text, intent="ask"))

    assert any(long_text in call for call in calls)


# ---------------------------------------------------------------------------
# The advisory layer must never stall the decision path on a cold model load
# ---------------------------------------------------------------------------


def test_cold_model_is_skipped_instead_of_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Loading all-MiniLM-L6-v2 costs ~5s in a fresh process. An advisory signal must
    never hold up a verdict for that long, so a cold model is declined, not awaited.
    """
    import aetherya.constitution as constitution_module

    def _must_not_be_called(_name: str) -> object:
        raise AssertionError("cold model load inside the decision path")

    monkeypatch.setattr(constitution_module, "_MODEL_CACHE", {})
    monkeypatch.setattr(constitution_module, "_default_model_factory", _must_not_be_called)

    core = Constitution([_principle()], use_semantic=True)
    result = core.evaluate(ActionRequest(raw_input="please assist with planning", intent="ask"))

    assert result["semantic_skipped"] == "model_not_warm"
    assert result["allowed"] is True


def test_warm_model_enables_the_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.constitution as constitution_module

    monkeypatch.setitem(
        constitution_module._MODEL_CACHE, DEFAULT_SEMANTIC_MODEL, _MaxSimilarityModel()
    )
    core = Constitution([_principle()], use_semantic=True)
    result = core.evaluate(ActionRequest(raw_input="please assist with planning", intent="ask"))

    assert "semantic_skipped" not in result
    assert "semantic_score" in result


def test_warm_requirement_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deployments that accept the cold-load cost can opt back in."""
    import aetherya.constitution as constitution_module

    monkeypatch.setattr(constitution_module, "_MODEL_CACHE", {})
    monkeypatch.setattr(
        constitution_module, "_default_model_factory", lambda _name: _MaxSimilarityModel()
    )
    core = Constitution([_principle()], use_semantic=True, require_warm_semantic_model=False)
    result = core.evaluate(ActionRequest(raw_input="please assist with planning", intent="ask"))

    assert "semantic_skipped" not in result


def test_injected_factory_counts_as_warm() -> None:
    """An explicitly supplied model is by definition ready."""
    evaluator = SemanticEvaluator([_principle()], model_factory=lambda _n: _MaxSimilarityModel())
    assert evaluator.can_evaluate() is True


def test_evaluator_error_is_recorded_as_a_skip_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.constitution as constitution_module

    class _Exploding:
        def encode(self, texts: list[str]) -> object:
            raise RuntimeError("model died")

    monkeypatch.setitem(constitution_module._MODEL_CACHE, DEFAULT_SEMANTIC_MODEL, _Exploding())
    core = Constitution([_principle()], use_semantic=True)
    result = core.evaluate(ActionRequest(raw_input="please assist with planning", intent="ask"))

    assert result["semantic_skipped"] == "evaluator_error"
    assert result["allowed"] is True


def test_pipeline_audits_the_skip_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A skipped advisory layer must be distinguishable from one that found nothing."""
    import json

    import aetherya.constitution as constitution_module
    from aetherya.audit import AuditLogger
    from aetherya.pipeline import run_pipeline

    monkeypatch.setattr(constitution_module, "_MODEL_CACHE", {})
    core = Constitution([_principle()], use_semantic=True)
    audit_path = tmp_path / "decisions.jsonl"

    run_pipeline(
        "please assist with the quarterly planning document",
        core,
        "robert",
        load_policy_config("config/policy.yaml"),
        audit=AuditLogger(str(audit_path)),
    )

    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["context"]["constitution"]["semantic_skipped"] == "model_not_warm"


def test_policy_exposes_the_warm_model_requirement() -> None:
    cfg = load_policy_config("config/policy.yaml")
    assert cfg.constitution_config.require_warm_semantic_model is True


# ---------------------------------------------------------------------------
# Policy load rejects an authoritative semantic layer
# ---------------------------------------------------------------------------


def _policy_with(**constitution_overrides: object) -> Path:
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    data["constitution"].update(constitution_overrides)
    handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    yaml.safe_dump(data, handle)
    handle.close()
    return Path(handle.name)


def test_policy_load_rejects_max_risk_at_or_above_deny_threshold() -> None:
    path = _policy_with(semantic_max_risk=80)  # == operative deny_at
    with pytest.raises(ValueError, match="may only escalate, never deny"):
        load_policy_config(path)


def test_policy_load_rejects_out_of_range_max_risk() -> None:
    with pytest.raises(ValueError, match=r"semantic_max_risk must be in \[1, 100\]"):
        load_policy_config(_policy_with(semantic_max_risk=0))


def test_authority_check_is_skipped_when_semantic_is_disabled() -> None:
    """With the learned layer off there is no authority to constrain."""
    cfg = load_policy_config(_policy_with(use_semantic=False, semantic_max_risk=99))
    assert cfg.constitution_config.use_semantic is False
    assert cfg.constitution_config.semantic_max_risk == 99


def test_default_policy_satisfies_the_invariant() -> None:
    cfg = load_policy_config("config/policy.yaml")
    assert cfg.constitution_config.semantic_max_risk == DEFAULT_SEMANTIC_MAX_RISK
    for mode_cfg in cfg.modes.values():
        assert cfg.constitution_config.semantic_max_risk < mode_cfg.thresholds.deny_at
