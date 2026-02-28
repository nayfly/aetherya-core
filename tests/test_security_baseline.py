from __future__ import annotations

import json
from pathlib import Path

import pytest

import aetherya.security_baseline as security_baseline


class _Decision:
    def __init__(self, *, allowed: bool, risk_score: int, violated_principle: str | None) -> None:
        self.allowed = allowed
        self.risk_score = risk_score
        self.violated_principle = violated_principle


def test_resolve_attestation_key_prefers_explicit_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AETHERYA_ATTESTATION_KEY", "env-key")
    assert (
        security_baseline._resolve_attestation_key("explicit-key") == "explicit-key"
    )  # noqa: SLF001
    assert security_baseline._resolve_attestation_key(None) == "env-key"  # noqa: SLF001


def test_resolve_attestation_key_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AETHERYA_ATTESTATION_KEY", raising=False)
    assert security_baseline._resolve_attestation_key(None) == "baseline-key"  # noqa: SLF001


def test_load_cases_rejects_invalid_payload(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid corpus payload"):
        security_baseline._load_cases(path)  # noqa: SLF001


def test_load_cases_rejects_invalid_version(tmp_path: Path) -> None:
    path = tmp_path / "invalid_version.json"
    path.write_text(json.dumps({"version": "v2", "cases": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported corpus version"):
        security_baseline._load_cases(path)  # noqa: SLF001


def test_load_cases_rejects_non_list_cases(tmp_path: Path) -> None:
    path = tmp_path / "invalid_cases.json"
    path.write_text(json.dumps({"version": "v1", "cases": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="corpus cases must be list"):
        security_baseline._load_cases(path)  # noqa: SLF001


def test_load_cases_rejects_empty_cases(tmp_path: Path) -> None:
    path = tmp_path / "empty_cases.json"
    path.write_text(json.dumps({"version": "v1", "cases": ["bad"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="corpus has no cases"):
        security_baseline._load_cases(path)  # noqa: SLF001


def test_load_baseline_rejects_invalid_payload(tmp_path: Path) -> None:
    path = tmp_path / "invalid_baseline.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid baseline payload"):
        security_baseline._load_baseline(path)  # noqa: SLF001


def test_load_baseline_rejects_invalid_version(tmp_path: Path) -> None:
    path = tmp_path / "invalid_baseline_version.json"
    path.write_text(json.dumps({"version": "v2", "metrics": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported baseline version"):
        security_baseline._load_baseline(path)  # noqa: SLF001


def test_load_baseline_rejects_non_dict_metrics(tmp_path: Path) -> None:
    path = tmp_path / "invalid_baseline_metrics.json"
    path.write_text(json.dumps({"version": "v1", "metrics": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="baseline metrics must be dict"):
        security_baseline._load_baseline(path)  # noqa: SLF001


def test_diff_values_detects_missing_and_list_length_and_root_mismatch() -> None:
    differences: list[dict] = []
    security_baseline._diff_values(  # noqa: SLF001
        expected={"a": 1, "b": [1, 2], "c": {"x": 1}},
        actual={"a": 2, "b": [1], "d": 5},
        path="",
        differences=differences,
    )
    paths = {str(diff["path"]) for diff in differences}
    assert "a" in paths
    assert "b" in paths
    assert "c" in paths
    assert "d" in paths


def test_diff_values_detects_list_item_mismatch() -> None:
    differences: list[dict] = []
    security_baseline._diff_values(  # noqa: SLF001
        expected=[{"x": 1}],
        actual=[{"x": 2}],
        path="items",
        differences=differences,
    )
    assert differences[0]["path"] == "items[0].x"


def test_compute_security_baseline_metrics_rejects_invalid_parameters(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="integrity_events must be > 0"):
        security_baseline.compute_security_baseline_metrics(
            policy_path=Path("config/policy.yaml"),
            attacks_path=Path("tests/fixtures/security_corpus/v1/jailbreak_attacks.json"),
            benign_path=Path("tests/fixtures/security_corpus/v1/benign_security_prompts.json"),
            workdir=tmp_path / "w1",
            attestation_key="key",
            integrity_events=0,
            integrity_tamper_stride=15,
            fuzz_events=160,
            fuzz_seed=1337,
            fuzz_rounds=18,
        )
    with pytest.raises(ValueError, match="integrity_tamper_stride must be > 0"):
        security_baseline.compute_security_baseline_metrics(
            policy_path=Path("config/policy.yaml"),
            attacks_path=Path("tests/fixtures/security_corpus/v1/jailbreak_attacks.json"),
            benign_path=Path("tests/fixtures/security_corpus/v1/benign_security_prompts.json"),
            workdir=tmp_path / "w2",
            attestation_key="key",
            integrity_events=1,
            integrity_tamper_stride=0,
            fuzz_events=160,
            fuzz_seed=1337,
            fuzz_rounds=18,
        )
    with pytest.raises(ValueError, match="fuzz_events must be > 0"):
        security_baseline.compute_security_baseline_metrics(
            policy_path=Path("config/policy.yaml"),
            attacks_path=Path("tests/fixtures/security_corpus/v1/jailbreak_attacks.json"),
            benign_path=Path("tests/fixtures/security_corpus/v1/benign_security_prompts.json"),
            workdir=tmp_path / "w3",
            attestation_key="key",
            integrity_events=1,
            integrity_tamper_stride=1,
            fuzz_events=0,
            fuzz_seed=1337,
            fuzz_rounds=18,
        )
    with pytest.raises(ValueError, match="fuzz_rounds must be >= 0"):
        security_baseline.compute_security_baseline_metrics(
            policy_path=Path("config/policy.yaml"),
            attacks_path=Path("tests/fixtures/security_corpus/v1/jailbreak_attacks.json"),
            benign_path=Path("tests/fixtures/security_corpus/v1/benign_security_prompts.json"),
            workdir=tmp_path / "w4",
            attestation_key="key",
            integrity_events=1,
            integrity_tamper_stride=1,
            fuzz_events=1,
            fuzz_seed=1337,
            fuzz_rounds=-1,
        )


def test_run_security_baseline_passes_against_versioned_fixture(tmp_path: Path) -> None:
    result = security_baseline.run_security_baseline(
        baseline_path="tests/fixtures/security_baseline/v1/stress_baseline.json",
        workdir=tmp_path / "baseline",
    )
    assert result.passed is True
    assert result.differences == []


def test_run_security_baseline_detects_mismatch(tmp_path: Path) -> None:
    baseline_path = tmp_path / "bad_baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "version": "v1",
                "kind": "security_stress_baseline",
                "metrics": {"integrity": {"clean_invalid": 999}, "jailbreak": {}},
            }
        ),
        encoding="utf-8",
    )
    result = security_baseline.run_security_baseline(
        baseline_path=baseline_path,
        workdir=tmp_path / "baseline",
    )
    assert result.passed is False
    assert result.differences


def test_run_security_baseline_writes_new_file_when_missing(tmp_path: Path) -> None:
    baseline_path = tmp_path / "new_baseline.json"
    result = security_baseline.run_security_baseline(
        baseline_path=baseline_path,
        workdir=tmp_path / "baseline",
    )
    assert baseline_path.exists()
    assert result.passed is True


def test_read_events_skips_blank_and_non_dict_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text('\n[]\n{"event_id":"ok"}\n', encoding="utf-8")
    events = security_baseline._read_events(path)  # noqa: SLF001
    assert events == [{"event_id": "ok"}]


def test_reset_file_removes_existing_path(tmp_path: Path) -> None:
    path = tmp_path / "to_remove.jsonl"
    path.write_text("x", encoding="utf-8")
    security_baseline._reset_file(path)  # noqa: SLF001
    assert path.exists() is False


def test_compute_jailbreak_metrics_covers_benign_guard_hits_and_prompt_safety(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attacks_path = tmp_path / "attacks.json"
    benign_path = tmp_path / "benign.json"
    attacks_path.write_text(
        json.dumps({"version": "v1", "cases": [{"id": "a1", "text": "attack"}]}), encoding="utf-8"
    )
    benign_path.write_text(
        json.dumps({"version": "v1", "cases": [{"id": "b1", "text": "benign"}]}), encoding="utf-8"
    )

    class Guard:
        def evaluate(self, text: str):  # noqa: ANN001
            return {"risk_score": 95} if text in {"attack", "benign"} else None

    def _fake_pipeline(text: str, constitution, actor: str, cfg):  # noqa: ANN001
        if text == "attack":
            return _Decision(allowed=False, risk_score=90, violated_principle="PromptSafety")
        return _Decision(allowed=False, risk_score=15, violated_principle="PromptSafety")

    monkeypatch.setattr(security_baseline, "JailbreakGuard", Guard)
    monkeypatch.setattr(security_baseline, "load_policy_config", lambda path: object())
    monkeypatch.setattr(security_baseline, "run_pipeline", _fake_pipeline)

    out = security_baseline._compute_jailbreak_metrics(  # noqa: SLF001
        attacks_path=attacks_path,
        benign_path=benign_path,
        policy_path=Path("config/policy.yaml"),
    )
    assert out["attacks_guard_hits"] == 1
    assert out["benign_guard_hits"] == 1
    assert out["benign_allowed"] == 0
    assert out["benign_prompt_safety_violations"] == 1


def test_compute_jailbreak_metrics_covers_attack_without_guard_and_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attacks_path = tmp_path / "attacks.json"
    benign_path = tmp_path / "benign.json"
    attacks_path.write_text(
        json.dumps({"version": "v1", "cases": [{"id": "a1", "text": "attack"}]}), encoding="utf-8"
    )
    benign_path.write_text(
        json.dumps({"version": "v1", "cases": [{"id": "b1", "text": "benign"}]}), encoding="utf-8"
    )

    class Guard:
        def evaluate(self, text: str):  # noqa: ANN001
            return None if text == "attack" else {"risk_score": 95}

    def _fake_pipeline(text: str, constitution, actor: str, cfg):  # noqa: ANN001
        if text == "attack":
            return _Decision(allowed=True, risk_score=5, violated_principle=None)
        return _Decision(allowed=True, risk_score=0, violated_principle=None)

    monkeypatch.setattr(security_baseline, "JailbreakGuard", Guard)
    monkeypatch.setattr(security_baseline, "load_policy_config", lambda path: object())
    monkeypatch.setattr(security_baseline, "run_pipeline", _fake_pipeline)

    out = security_baseline._compute_jailbreak_metrics(  # noqa: SLF001
        attacks_path=attacks_path,
        benign_path=benign_path,
        policy_path=Path("config/policy.yaml"),
    )
    assert out["attacks_guard_hits"] == 0
    assert out["attacks_blocked"] == 0
    assert out["attacks_avg_guard_risk"] == 0.0


def test_compute_integrity_metrics_covers_small_fuzz_len_branches(tmp_path: Path) -> None:
    out = security_baseline._compute_integrity_metrics(  # noqa: SLF001
        workdir=tmp_path / "w",
        attestation_key="k",
        events=6,
        tamper_stride=2,
        fuzz_events=1,
        fuzz_seed=1337,
        fuzz_rounds=1,
    )
    assert out["integrity_events"] == 6
    assert out["fuzz_events"] == 1


def test_compute_integrity_metrics_covers_empty_fuzz_payload_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(security_baseline, "_read_events", lambda path: [])
    monkeypatch.setattr(security_baseline, "verify_audit_file", lambda *args, **kwargs: [])
    out = security_baseline._compute_integrity_metrics(  # noqa: SLF001
        workdir=tmp_path / "w",
        attestation_key="k",
        events=3,
        tamper_stride=1,
        fuzz_events=1,
        fuzz_seed=1337,
        fuzz_rounds=2,
    )
    assert out["fuzz_invalid"] == 0
    assert out["tampered_events"] == 0


def test_compute_integrity_metrics_covers_swap_same_index_and_small_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeRandom:
        def __init__(self, seed: int):  # noqa: ARG002
            self.calls = 0

        def randrange(self, n: int) -> int:
            sequence = [1, 0, 0]
            idx = sequence[self.calls] if self.calls < len(sequence) else 0
            self.calls += 1
            return idx % max(1, n)

    monkeypatch.setattr(security_baseline, "Random", FakeRandom)
    out = security_baseline._compute_integrity_metrics(  # noqa: SLF001
        workdir=tmp_path / "w",
        attestation_key="k",
        events=4,
        tamper_stride=2,
        fuzz_events=2,
        fuzz_seed=42,
        fuzz_rounds=1,
    )
    assert out["fuzz_events"] == 2


def test_format_text_result_for_pass_and_failure() -> None:
    pass_result = security_baseline.SecurityBaselineResult(
        passed=True,
        baseline_path="x.json",
        actual={},
        expected={},
        differences=[],
    )
    text_ok = security_baseline._format_text_result(pass_result)  # noqa: SLF001
    assert "security_baseline passed=True" in text_ok
    assert "differences: 0" in text_ok

    fail_result = security_baseline.SecurityBaselineResult(
        passed=False,
        baseline_path="x.json",
        actual={},
        expected={},
        differences=[
            {"path": "a", "expected": 1, "actual": 2},
            {"path": "b", "expected": 1, "actual": 3},
        ],
    )
    text_fail = security_baseline._format_text_result(fail_result, max_diff=1)  # noqa: SLF001
    assert "security_baseline passed=False" in text_fail
    assert "... 1 more differences" in text_fail


def test_format_text_result_for_failure_without_truncation() -> None:
    fail_result = security_baseline.SecurityBaselineResult(
        passed=False,
        baseline_path="x.json",
        actual={},
        expected={},
        differences=[{"path": "a", "expected": 1, "actual": 2}],
    )
    text = security_baseline._format_text_result(fail_result, max_diff=5)  # noqa: SLF001
    assert "differences: 1" in text
    assert "... " not in text


def test_main_json_mode_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    baseline_path = tmp_path / "baseline.json"
    code = security_baseline.main(
        [
            "--baseline-path",
            str(baseline_path),
            "--workdir",
            str(tmp_path / "work"),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert code == 0
    assert payload["passed"] is True


def test_main_text_mode_returns_fail_on_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline_path = tmp_path / "bad.json"
    baseline_path.write_text(
        json.dumps({"version": "v1", "kind": "security_stress_baseline", "metrics": {"x": 1}}),
        encoding="utf-8",
    )
    code = security_baseline.main(
        [
            "--baseline-path",
            str(baseline_path),
            "--workdir",
            str(tmp_path / "work"),
            "--max-diff",
            "1",
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "security_baseline passed=False" in captured.out


def test_main_returns_error_on_value_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom(**kwargs):  # noqa: ANN001
        raise ValueError("boom")

    monkeypatch.setattr(security_baseline, "run_security_baseline", _boom)
    code = security_baseline.main([])
    captured = capsys.readouterr()
    assert code == 2
    assert "error: boom" in captured.err
