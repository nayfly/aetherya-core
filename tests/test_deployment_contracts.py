from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml

from aetherya.api import AetheryaAPI, APISettings
from aetherya.audit import AuditEvent, AuditLogger
from aetherya.config import (
    POLICY_FINGERPRINT_ENV,
    PolicyFingerprintMismatch,
    expected_policy_fingerprint,
    load_policy_config,
)
from aetherya.constitution import DEFAULT_SEMANTIC_MODEL

_POLICY = "config/policy.yaml"


# ---------------------------------------------------------------------------
# Policy version contract
# ---------------------------------------------------------------------------


def test_matching_pin_loads_normally(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pin is the *effective* fingerprint — behaviour, not file bytes."""
    fingerprint = load_policy_config(_POLICY).effective_fingerprint
    assert fingerprint is not None
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, fingerprint)
    assert load_policy_config(_POLICY).effective_fingerprint == fingerprint


def test_mismatched_pin_refuses_to_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Two replicas on different policies return different decisions for identical
    input, and nothing surfaces that until someone diffs audit trails. Pinning
    turns silent divergence into a startup failure.
    """
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, "sha256:deadbeef")
    with pytest.raises(PolicyFingerprintMismatch) as excinfo:
        load_policy_config(_POLICY)

    assert excinfo.value.expected == "sha256:deadbeef"
    assert "divergent decisions" in str(excinfo.value)


def test_explicit_pin_overrides_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    fingerprint = load_policy_config(_POLICY).effective_fingerprint
    assert fingerprint is not None
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, "sha256:ignored")
    assert load_policy_config(_POLICY, expected_fingerprint=fingerprint) is not None


def test_no_pin_means_no_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(POLICY_FINGERPRINT_ENV, raising=False)
    assert load_policy_config(_POLICY) is not None


@pytest.mark.parametrize(
    ("explicit", "env", "expected"),
    [
        (None, "", None),
        (None, "  sha256:x ", "sha256:x"),
        ("  ", "sha256:from-env", None),
        ("sha256:explicit", "sha256:from-env", "sha256:explicit"),
    ],
)
def test_expected_fingerprint_resolution(
    monkeypatch: pytest.MonkeyPatch, explicit: str | None, env: str, expected: str | None
) -> None:
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, env)
    assert expected_policy_fingerprint(explicit) == expected


def test_a_changed_policy_changes_the_fingerprint(tmp_path: Path) -> None:
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["modes"]["operative"]["thresholds"]["deny_at"] = 70
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    assert (
        load_policy_config(path).policy_fingerprint
        != load_policy_config(_POLICY).policy_fingerprint
    )


# ---------------------------------------------------------------------------
# Health: policy pin and semantic readiness
# ---------------------------------------------------------------------------


def _api(tmp_path: Path) -> AetheryaAPI:
    return AetheryaAPI(APISettings(audit_path=tmp_path / "decisions.jsonl"))


def test_health_reports_the_policy_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fingerprint = load_policy_config(_POLICY).effective_fingerprint
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, str(fingerprint))

    code, body = _api(tmp_path).health()
    assert code == 200
    assert body["policy_fingerprint_pinned"] == fingerprint
    assert body["policy_fingerprint_match"] is True


def test_health_reports_no_pin_as_matching(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(POLICY_FINGERPRINT_ENV, raising=False)
    _, body = _api(tmp_path).health()
    assert body["policy_fingerprint_pinned"] is None
    assert body["policy_fingerprint_match"] is True


def test_health_reports_degraded_when_the_semantic_layer_is_cold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The advisory layer silently declines to run on a cold model. Without this
    signal an operator cannot tell that the layer they configured is inert.
    """
    import aetherya.constitution as constitution_module

    monkeypatch.setattr(constitution_module, "_MODEL_CACHE", {})
    _, body = _api(tmp_path).health()

    assert body["semantic_enabled"] is True
    assert body["semantic_model_warm"] is False
    assert body["semantic_ready"] is False
    assert body["degraded"] is True


def test_health_reports_ready_once_the_model_is_warm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aetherya.constitution as constitution_module

    monkeypatch.setitem(constitution_module._MODEL_CACHE, DEFAULT_SEMANTIC_MODEL, object())
    _, body = _api(tmp_path).health()

    assert body["semantic_ready"] is True
    assert body["degraded"] is False


def test_health_is_not_degraded_when_semantic_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aetherya.constitution as constitution_module

    monkeypatch.setattr(constitution_module, "_MODEL_CACHE", {})
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["constitution"]["use_semantic"] = False
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(data), encoding="utf-8")

    api = AetheryaAPI(APISettings(policy_path=policy, audit_path=tmp_path / "a.jsonl"))
    _, body = api.health()

    assert body["semantic_enabled"] is False
    assert body["degraded"] is False


def test_health_is_not_degraded_when_the_warm_requirement_is_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aetherya.constitution as constitution_module

    monkeypatch.setattr(constitution_module, "_MODEL_CACHE", {})
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["constitution"]["require_warm_semantic_model"] = False
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(data), encoding="utf-8")

    api = AetheryaAPI(APISettings(policy_path=policy, audit_path=tmp_path / "a.jsonl"))
    _, body = api.health()
    assert body["degraded"] is False


def test_health_fails_closed_on_a_pinned_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, "sha256:wrong")
    code, body = _api(tmp_path).health()

    assert code == 503
    assert body["ok"] is False
    assert body["error_type"] == "PolicyFingerprintMismatch"


# ---------------------------------------------------------------------------
# Audit durability and mirroring
# ---------------------------------------------------------------------------


class RecordingSink:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, event: AuditEvent, line: str) -> None:
        self.lines.append(line)


class FailingSink:
    def write(self, event: AuditEvent, line: str) -> None:
        raise ConnectionError("archive unreachable")


def _log(logger: AuditLogger) -> None:
    logger.log(actor="robert", action="do thing", decision={"allowed": True}, context={})


def test_mirror_receives_the_exact_primary_line(tmp_path: Path) -> None:
    """Byte-identical lines mean the chain verifies the same on either copy."""
    sink = RecordingSink()
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    _log(logger)

    written = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    assert sink.lines == written


def test_mirror_failure_is_counted_not_raised(tmp_path: Path) -> None:
    """A transient archive outage must not take the decision path down."""
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[FailingSink()])
    _log(logger)
    _log(logger)

    assert logger.mirror_errors == 2
    assert len((tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_multiple_mirrors_all_receive_the_event(tmp_path: Path) -> None:
    first, second = RecordingSink(), RecordingSink()
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[first, FailingSink(), second])
    _log(logger)

    assert len(first.lines) == 1
    assert len(second.lines) == 1
    assert logger.mirror_errors == 1


def test_fsync_is_off_by_default_and_opt_in(tmp_path: Path) -> None:
    assert AuditLogger(str(tmp_path / "a.jsonl")).fsync is False
    assert AuditLogger(str(tmp_path / "b.jsonl"), fsync=True).fsync is True


def test_fsync_still_produces_a_verifiable_chain(tmp_path: Path) -> None:
    from aetherya.audit_verify import verify_audit_file

    path = tmp_path / "a.jsonl"
    logger = AuditLogger(str(path), fsync=True)
    for _ in range(3):
        _log(logger)

    records = verify_audit_file(str(path), require_chain=True)
    assert len(records) == 3
    assert all(record.verification.valid for record in records)


def test_chain_tip_does_not_advance_when_the_primary_write_fails(tmp_path: Path) -> None:
    """
    The mirror is secondary: if the authoritative write fails, the next event
    must still chain onto the last durably recorded one.
    """
    path = tmp_path / "a.jsonl"
    logger = AuditLogger(str(path))
    _log(logger)
    tip_after_first = logger._chain_tip  # noqa: SLF001

    logger.path = tmp_path / "nonexistent-dir" / "a.jsonl"
    with pytest.raises(OSError):
        _log(logger)

    assert logger._chain_tip == tip_after_first  # noqa: SLF001


def test_verify_exit_codes_are_job_friendly(tmp_path: Path) -> None:
    """Periodic chain verification runs as a cron/k8s job; exit codes must be usable."""
    from aetherya.audit_verify import main as verify_main

    path = tmp_path / "a.jsonl"
    logger = AuditLogger(str(path))
    for _ in range(2):
        _log(logger)

    assert verify_main(["--audit-path", str(path), "--require-chain", "--json"]) == 0

    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    events[0]["actor"] = "tampered"
    path.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8"
    )
    assert verify_main(["--audit-path", str(path), "--require-chain", "--json"]) == 1

    missing = tmp_path / "missing.jsonl"
    assert verify_main(["--audit-path", str(missing), "--json"]) == 2


def test_audit_sink_protocol_accepts_a_structural_implementation(tmp_path: Path) -> None:
    from aetherya.audit import AuditSink

    sink: AuditSink = RecordingSink()
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    _log(logger)
    assert len(sink.lines) == 1  # type: ignore[attr-defined]


def test_mirrors_default_to_empty(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "a.jsonl"))
    assert logger.mirrors == []
    assert logger.mirror_errors == 0


# ---------------------------------------------------------------------------
# Server startup: semantic warmup
# ---------------------------------------------------------------------------


def test_startup_warms_the_semantic_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.api_server as server_module

    calls: list[str] = []
    monkeypatch.setattr(
        server_module, "warmup_semantic_model", lambda: calls.append("warmed") or {}
    )
    ready = server_module.warmup_semantic_layer(policy_path=Path(_POLICY))

    assert ready is True
    assert calls == ["warmed"]


def test_startup_warmup_can_be_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    import aetherya.api_server as server_module

    def _boom() -> dict[str, Any]:
        raise AssertionError("warmup should not run")

    monkeypatch.setattr(server_module, "warmup_semantic_model", _boom)
    assert (
        server_module.warmup_semantic_layer(policy_path=Path(_POLICY), warmup_semantic=False)
        is False
    )


def test_startup_skips_warmup_when_semantic_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aetherya.api_server as server_module

    def _boom() -> dict[str, Any]:
        raise AssertionError("warmup should not run")

    monkeypatch.setattr(server_module, "warmup_semantic_model", _boom)
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["constitution"]["use_semantic"] = False
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(data), encoding="utf-8")

    assert server_module.warmup_semantic_layer(policy_path=policy) is False


def test_startup_degrades_when_warmup_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Default posture: serve without the advisory layer rather than refuse traffic."""
    import aetherya.api_server as server_module

    def _boom() -> dict[str, Any]:
        raise RuntimeError("no model available")

    monkeypatch.setattr(server_module, "warmup_semantic_model", _boom)
    assert server_module.warmup_semantic_layer(policy_path=Path(_POLICY)) is False
    assert "semantic warmup failed" in capsys.readouterr().err


def test_strict_mode_fails_startup_when_warmup_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment that depends on the layer should not start without it."""
    import aetherya.api_server as server_module

    def _boom() -> dict[str, Any]:
        raise RuntimeError("no model available")

    monkeypatch.setattr(server_module, "warmup_semantic_model", _boom)
    with pytest.raises(RuntimeError, match="semantic layer requested but unavailable"):
        server_module.warmup_semantic_layer(policy_path=Path(_POLICY), require_semantic_ready=True)


# ---------------------------------------------------------------------------
# Effective fingerprint: behavioural identity, not file bytes
# ---------------------------------------------------------------------------


def test_cosmetic_edits_do_not_change_the_effective_fingerprint(tmp_path: Path) -> None:
    """
    Comments, key order and whitespace change the file hash but not behaviour.
    Pinning on file bytes would reject a reformatted but identical policy.
    """
    base = load_policy_config(_POLICY)
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))

    path = tmp_path / "reformatted.yaml"
    path.write_text(
        "# a completely different header comment\n" + yaml.safe_dump(data, sort_keys=True),
        encoding="utf-8",
    )
    reformatted = load_policy_config(path)

    assert reformatted.policy_fingerprint != base.policy_fingerprint
    assert reformatted.effective_fingerprint == base.effective_fingerprint


def test_a_behavioural_change_does_change_the_effective_fingerprint(tmp_path: Path) -> None:
    base = load_policy_config(_POLICY)
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["modes"]["operative"]["thresholds"]["deny_at"] = 70

    path = tmp_path / "behaviour.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    assert load_policy_config(path).effective_fingerprint != base.effective_fingerprint


def test_a_changed_code_default_changes_the_effective_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The case a file hash cannot see: the YAML omits a section and relies on a
    default, a code upgrade changes that default, and the engine now decides
    differently while the file is untouched. That is exactly the silent
    divergence pinning exists to catch.
    """
    import aetherya.config as config_module

    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data.pop("intent_escalation", None)
    path = tmp_path / "minimal.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    before = load_policy_config(path)
    monkeypatch.setattr(
        config_module,
        "_load_intent_escalation",
        lambda _raw: config_module.IntentEscalationConfig(enabled=False),
    )
    after = load_policy_config(path)

    assert after.policy_fingerprint == before.policy_fingerprint
    assert after.effective_fingerprint != before.effective_fingerprint


def test_the_pin_is_checked_against_the_effective_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = load_policy_config(_POLICY)
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, str(cfg.effective_fingerprint))
    assert load_policy_config(_POLICY) is not None

    # The file hash is not what the pin compares against.
    monkeypatch.setenv(POLICY_FINGERPRINT_ENV, str(cfg.policy_fingerprint))
    with pytest.raises(PolicyFingerprintMismatch):
        load_policy_config(_POLICY)


def test_the_fingerprint_fields_are_excluded_from_their_own_material() -> None:
    """Otherwise the hash would depend on itself and never stabilise."""
    from aetherya.config import compute_effective_fingerprint

    cfg = load_policy_config(_POLICY)
    assert compute_effective_fingerprint(cfg) == cfg.effective_fingerprint

    stripped = replace(cfg, policy_fingerprint=None, effective_fingerprint=None)
    assert compute_effective_fingerprint(stripped) == cfg.effective_fingerprint


def test_health_reports_both_fingerprints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(POLICY_FINGERPRINT_ENV, raising=False)
    cfg = load_policy_config(_POLICY)
    _, body = _api(tmp_path).health()

    assert body["policy_fingerprint"] == cfg.policy_fingerprint
    assert body["effective_fingerprint"] == cfg.effective_fingerprint


def test_cli_prints_both_fingerprints(capsys: pytest.CaptureFixture[str]) -> None:
    """Deployment pipelines need a command that emits the value to pin."""
    from aetherya.cli import main

    assert main(["policy", "fingerprint", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    cfg = load_policy_config(_POLICY)

    assert payload["effective_fingerprint"] == cfg.effective_fingerprint
    assert payload["policy_fingerprint"] == cfg.policy_fingerprint


def test_cli_fingerprint_text_output(capsys: pytest.CaptureFixture[str]) -> None:
    from aetherya.cli import main

    assert main(["policy", "fingerprint"]) == 0
    out = capsys.readouterr().out
    assert "effective_fingerprint" in out
    assert "policy_fingerprint" in out


# ---------------------------------------------------------------------------
# The HTTP API must actually apply the configured rate limit
# ---------------------------------------------------------------------------


def test_api_enforces_the_configured_rate_limit(tmp_path: Path) -> None:
    """
    Regression: `rate_limit` was validated on load and `build_rate_limiter`
    worked, but nothing in the HTTP path ever constructed a limiter — the
    configured limit was documentation, not behaviour.
    """
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["rate_limit"].update({"backend": "memory", "requests_per_window": 3})
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(data), encoding="utf-8")

    api = AetheryaAPI(APISettings(policy_path=policy, audit_path=tmp_path / "a.jsonl"))
    states = []
    for _ in range(5):
        _, body = api.decide({"raw_input": "help user", "actor": "chatty", "wait_shadow": False})
        states.append(body["decision"]["allowed"])

    assert states[:3] == [True, True, True]
    assert states[3:] == [False, False]


def test_the_limiter_is_built_once_and_reused(tmp_path: Path) -> None:
    """Rebuilding per request would reset every window and make it a no-op."""
    api = AetheryaAPI(APISettings(audit_path=tmp_path / "a.jsonl"))
    cfg = load_policy_config(_POLICY)

    first = api._resolve_rate_limiter(cfg)  # noqa: SLF001
    assert api._resolve_rate_limiter(cfg) is first  # noqa: SLF001


def test_the_limiter_is_rebuilt_when_the_policy_changes(tmp_path: Path) -> None:
    api = AetheryaAPI(APISettings(audit_path=tmp_path / "a.jsonl"))
    cfg = load_policy_config(_POLICY)
    first = api._resolve_rate_limiter(cfg)  # noqa: SLF001

    changed = replace(cfg, rate_limit=replace(cfg.rate_limit, requests_per_window=7))
    assert api._resolve_rate_limiter(changed) is not first  # noqa: SLF001


def test_a_config_without_a_rate_limit_section_disables_limiting(tmp_path: Path) -> None:
    class _Cfg:
        pass

    api = AetheryaAPI(APISettings(audit_path=tmp_path / "a.jsonl"))
    assert api._resolve_rate_limiter(_Cfg()) is None  # noqa: SLF001


def test_the_pipeline_accepts_any_limiter_backend() -> None:
    """
    The signature said `ActorRateLimiter`, so the Redis backend could not be
    passed to the pipeline at all — mypy caught it once the API wired it up.
    """
    import inspect

    from aetherya.pipeline import run_pipeline

    annotation = inspect.signature(run_pipeline).parameters["rate_limiter"].annotation
    assert "RateLimiter" in str(annotation)
    assert "ActorRateLimiter" not in str(annotation)


def test_the_slim_policy_differs_only_in_the_semantic_layer() -> None:
    """
    `config/policy.slim.yaml` exists so the image can drop PyTorch (~8.7GB ->
    ~330MB). That is only safe because the semantic layer is advisory: capped
    below every deny threshold, it can escalate to a human but never refuse
    alone, so disabling it changes nothing about what is hard-denied. Three
    policy files is a drift hazard, so the difference is pinned to one field.
    """
    from dataclasses import asdict

    docker = load_policy_config("config/policy.docker.yaml")
    slim = load_policy_config("config/policy.slim.yaml")

    assert docker.constitution_config.use_semantic is True
    assert slim.constitution_config.use_semantic is False

    ignored = {"policy_fingerprint", "effective_fingerprint", "constitution_config"}
    assert {k: v for k, v in asdict(docker).items() if k not in ignored} == {
        k: v for k, v in asdict(slim).items() if k not in ignored
    }
    assert replace(docker.constitution_config, use_semantic=False) == slim.constitution_config


def test_the_deployment_policy_differs_only_where_it_is_meant_to() -> None:
    """
    `config/policy.docker.yaml` exists so the container gets the distributed
    limiter and cryptographically bound approvals, while the repo default keeps
    working with no infrastructure at all. Two policy files is a drift hazard,
    so the differences are pinned to exactly these two — anything else changing
    in one and not the other fails here.

    Signed proofs are on in the container because it ships the approval queue.
    An approval that is not bound to the exact action is a token anyone can
    type; the repo default stays off so `aetherya decide` needs no key
    management to be useful.
    """
    from dataclasses import asdict

    repo = load_policy_config(_POLICY)
    docker = load_policy_config("config/policy.docker.yaml")

    assert repo.rate_limit.backend == "memory"
    assert docker.rate_limit.backend == "redis"
    assert repo.confirmation.evidence.signed_proof.enabled is False
    assert docker.confirmation.evidence.signed_proof.enabled is True

    ignored = {"policy_fingerprint", "effective_fingerprint", "rate_limit", "confirmation"}
    repo_fields = {k: v for k, v in asdict(repo).items() if k not in ignored}
    docker_fields = {k: v for k, v in asdict(docker).items() if k not in ignored}
    assert repo_fields == docker_fields

    assert replace(repo.rate_limit, backend="redis") == docker.rate_limit
    # Confirmation must be identical apart from that one flag.
    repo_evidence = repo.confirmation.evidence
    docker_evidence = docker.confirmation.evidence
    assert replace(
        repo.confirmation,
        evidence=replace(
            repo_evidence,
            signed_proof=replace(repo_evidence.signed_proof, enabled=True),
        ),
    ) == replace(
        docker.confirmation,
        evidence=replace(
            docker_evidence,
            signed_proof=replace(docker_evidence.signed_proof, enabled=True),
        ),
    )
