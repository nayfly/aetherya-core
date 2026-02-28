from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aetherya.security_gate import main, run_security_gate

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "security_corpus" / "v1"


def _phase_by_name(phases: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for phase in phases:
        if str(phase.get("name", "")) == name:
            return phase
    raise AssertionError(f"phase not found: {name}")


def test_run_security_gate_passes_and_writes_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "security_manifest.json"
    commit_sha = "abc123release"
    result = run_security_gate(
        attestation_key="gate-key",
        commit_sha=commit_sha,
        attacks_path=_FIXTURE_DIR / "jailbreak_attacks.json",
        snapshots_path=_FIXTURE_DIR / "attack_decision_snapshots.json",
        workdir=tmp_path / "gate_work",
        manifest_output=manifest,
        phase2_events=120,
        phase2_mutation_rounds=10,
    )

    assert result.passed is True
    assert result.manifest_path == str(manifest)
    assert manifest.exists()

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["signature_alg"] == "hmac-sha256"
    assert str(payload["signature"]).startswith("hmac-sha256:")
    assert payload["decision_count"] == len(
        json.loads((_FIXTURE_DIR / "jailbreak_attacks.json").read_text(encoding="utf-8"))["cases"]
    )
    assert payload["commit_sha"] == commit_sha


def test_run_security_gate_phase1_snapshot_failure_generates_reports(tmp_path: Path) -> None:
    bad_snapshot = tmp_path / "bad_snapshots.json"
    payload = json.loads(
        (_FIXTURE_DIR / "attack_decision_snapshots.json").read_text(encoding="utf-8")
    )
    payload["cases"][0]["expected"]["risk_score"] = 91
    bad_snapshot.write_text(json.dumps(payload), encoding="utf-8")

    reports_dir = tmp_path / "reports"
    result = run_security_gate(
        attestation_key="gate-key",
        attacks_path=_FIXTURE_DIR / "jailbreak_attacks.json",
        snapshots_path=bad_snapshot,
        workdir=tmp_path / "gate_work",
        failure_report_dir=reports_dir,
        manifest_output=tmp_path / "manifest.json",
        phase2_events=120,
        phase2_mutation_rounds=8,
    )

    assert result.passed is False
    phase_1 = next(phase for phase in result.phases if phase.name == "phase_1_corpus_regression")
    assert phase_1.passed is False
    assert phase_1.details["failed_cases"] >= 1
    assert reports_dir.exists()
    assert list(reports_dir.glob("*.html"))


def test_run_security_gate_phase2_requires_exact_reject_code(tmp_path: Path) -> None:
    result = run_security_gate(
        attestation_key="gate-key",
        attacks_path=_FIXTURE_DIR / "jailbreak_attacks.json",
        snapshots_path=_FIXTURE_DIR / "attack_decision_snapshots.json",
        workdir=tmp_path / "gate_work",
        manifest_output=tmp_path / "manifest.json",
        phase2_events=120,
        phase2_mutation_rounds=8,
        phase2_expected_reject_code=2,
    )

    assert result.passed is False
    phase_2 = next(phase for phase in result.phases if phase.name == "phase_2_integrity_fuzz")
    assert phase_2.passed is False
    assert phase_2.details["actual_code"] == 1
    assert phase_2.details["expected_reject_code"] == 2


def test_main_json_mode_emits_machine_readable_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "--attestation-key",
            "gate-key",
            "--attacks-path",
            str(_FIXTURE_DIR / "jailbreak_attacks.json"),
            "--snapshots-path",
            str(_FIXTURE_DIR / "attack_decision_snapshots.json"),
            "--workdir",
            str(tmp_path / "gate_work"),
            "--manifest-output",
            str(tmp_path / "manifest.json"),
            "--phase2-events",
            "120",
            "--phase2-mutation-rounds",
            "8",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())

    assert code == 0
    assert payload["passed"] is True
    assert payload["manifest_path"] == str(tmp_path / "manifest.json")
    phases = payload["phases"]
    assert isinstance(phases, list)
    assert _phase_by_name(phases, "phase_1_corpus_regression")["passed"] is True
    assert _phase_by_name(phases, "phase_2_integrity_fuzz")["passed"] is True
    assert _phase_by_name(phases, "phase_3_release_attestation")["passed"] is True


def test_main_returns_error_when_attestation_key_is_missing(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AETHERYA_ATTESTATION_KEY", raising=False)
    code = main(["--json"])
    captured = capsys.readouterr()

    assert code == 2
    assert "attestation key is required" in captured.err
