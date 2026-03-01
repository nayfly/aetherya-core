from __future__ import annotations

import json
from pathlib import Path

import pytest

import aetherya.verify_release_artifacts as verify_release_artifacts
from aetherya.security_gate import run_security_gate
from aetherya.verify_release_artifacts import (
    main,
    run_release_artifact_verification,
)

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "security_corpus" / "v1"


def _attack_count() -> int:
    payload = json.loads((_FIXTURE_DIR / "jailbreak_attacks.json").read_text(encoding="utf-8"))
    return len(payload["cases"])


def _generate_valid_manifest(tmp_path: Path, commit_sha: str = "abc123") -> tuple[Path, Path]:
    workdir = tmp_path / "gate_work"
    manifest = tmp_path / "security_manifest.json"
    result = run_security_gate(
        attestation_key="gate-key",
        commit_sha=commit_sha,
        attacks_path=_FIXTURE_DIR / "jailbreak_attacks.json",
        snapshots_path=_FIXTURE_DIR / "attack_decision_snapshots.json",
        workdir=workdir,
        manifest_output=manifest,
        phase2_events=120,
        phase2_mutation_rounds=8,
    )
    assert result.passed is True
    return manifest, workdir / "phase1_corpus_audit.jsonl"


def test_run_release_artifact_verification_passes(tmp_path: Path) -> None:
    commit_sha = "deadbeef"
    manifest, phase1_audit = _generate_valid_manifest(tmp_path, commit_sha=commit_sha)

    result = run_release_artifact_verification(
        manifest_path=manifest,
        phase1_audit_path=phase1_audit,
        expected_commit_sha=commit_sha,
        corpus_path=_FIXTURE_DIR / "jailbreak_attacks.json",
        attestation_key="gate-key",
    )
    assert result.passed is True
    assert result.signature_valid is True
    assert result.observed_decision_count == _attack_count()
    assert result.phase1_audit_line_count == _attack_count()
    assert result.errors == []


def test_run_release_artifact_verification_fails_when_manifest_is_empty(tmp_path: Path) -> None:
    manifest = tmp_path / "security_manifest.json"
    manifest.write_text("\n", encoding="utf-8")

    result = run_release_artifact_verification(
        manifest_path=manifest,
        expected_commit_sha="deadbeef",
        expected_decision_count=1,
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert result.signature_valid is False
    assert any("manifest is empty" in err for err in result.errors)


def test_run_release_artifact_verification_fails_when_manifest_not_found(tmp_path: Path) -> None:
    missing_manifest = tmp_path / "missing_manifest.json"
    result = run_release_artifact_verification(
        manifest_path=missing_manifest,
        expected_commit_sha="deadbeef",
        expected_decision_count=1,
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("manifest file not found" in err for err in result.errors)


def test_run_release_artifact_verification_fails_for_invalid_manifest_json(tmp_path: Path) -> None:
    manifest = tmp_path / "security_manifest.json"
    manifest.write_text("{invalid-json", encoding="utf-8")
    result = run_release_artifact_verification(
        manifest_path=manifest,
        expected_commit_sha="deadbeef",
        expected_decision_count=1,
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("invalid JSON" in err for err in result.errors)


def test_run_release_artifact_verification_fails_for_manifest_invalid_utf8(tmp_path: Path) -> None:
    manifest = tmp_path / "security_manifest.json"
    manifest.write_bytes(b"\xff\xfe\x00")
    result = run_release_artifact_verification(
        manifest_path=manifest,
        expected_commit_sha="deadbeef",
        expected_decision_count=1,
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("manifest is not valid UTF-8" in err for err in result.errors)


def test_run_release_artifact_verification_fails_for_non_object_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "security_manifest.json"
    manifest.write_text(json.dumps(["bad"]), encoding="utf-8")
    result = run_release_artifact_verification(
        manifest_path=manifest,
        expected_commit_sha="deadbeef",
        expected_decision_count=1,
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("manifest root must be JSON object" in err for err in result.errors)


def test_run_release_artifact_verification_fails_on_commit_mismatch(tmp_path: Path) -> None:
    manifest, phase1_audit = _generate_valid_manifest(tmp_path, commit_sha="good-commit")
    result = run_release_artifact_verification(
        manifest_path=manifest,
        phase1_audit_path=phase1_audit,
        expected_commit_sha="other-commit",
        expected_decision_count=_attack_count(),
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("commit_sha mismatch" in err for err in result.errors)


def test_run_release_artifact_verification_fails_on_signature_tamper(tmp_path: Path) -> None:
    manifest, _ = _generate_valid_manifest(tmp_path, commit_sha="good-commit")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["decision_count"] = int(payload["decision_count"]) + 1
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = run_release_artifact_verification(
        manifest_path=manifest,
        expected_commit_sha="good-commit",
        expected_decision_count=_attack_count(),
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert result.signature_valid is False
    assert any("signature is invalid" in err for err in result.errors)


def test_run_release_artifact_verification_fails_for_invalid_decision_count_type(
    tmp_path: Path,
) -> None:
    manifest, _ = _generate_valid_manifest(tmp_path, commit_sha="good-commit")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["decision_count"] = "bad-count"
    manifest.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = run_release_artifact_verification(
        manifest_path=manifest,
        expected_commit_sha="good-commit",
        expected_decision_count=_attack_count(),
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("decision_count missing or invalid type" in err for err in result.errors)


def test_run_release_artifact_verification_fails_for_phase1_count_mismatch(tmp_path: Path) -> None:
    manifest, phase1_audit = _generate_valid_manifest(tmp_path, commit_sha="good-commit")
    phase1_audit.write_text('{"event_id":"only-one"}\n', encoding="utf-8")

    result = run_release_artifact_verification(
        manifest_path=manifest,
        phase1_audit_path=phase1_audit,
        expected_commit_sha="good-commit",
        expected_decision_count=_attack_count(),
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("phase1 audit event count mismatch" in err for err in result.errors)


def test_run_release_artifact_verification_fails_for_empty_phase1_audit(tmp_path: Path) -> None:
    manifest, _ = _generate_valid_manifest(tmp_path, commit_sha="good-commit")
    empty_audit = tmp_path / "phase1_empty.jsonl"
    empty_audit.write_text("\n", encoding="utf-8")
    result = run_release_artifact_verification(
        manifest_path=manifest,
        phase1_audit_path=empty_audit,
        expected_commit_sha="good-commit",
        expected_decision_count=_attack_count(),
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("audit file is empty" in err for err in result.errors)


def test_run_release_artifact_verification_requires_attestation_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("AETHERYA_ATTESTATION_KEY", raising=False)
    with pytest.raises(ValueError, match="attestation key is required"):
        run_release_artifact_verification(
            manifest_path=tmp_path / "manifest.json",
            expected_commit_sha="abc",
            expected_decision_count=1,
            attestation_key=None,
        )


def test_run_release_artifact_verification_rejects_empty_expected_commit() -> None:
    with pytest.raises(ValueError, match="expected_commit_sha must be non-empty"):
        run_release_artifact_verification(
            expected_commit_sha=" ",
            expected_decision_count=1,
            attestation_key="gate-key",
        )


def test_load_expected_decision_count_error_paths(tmp_path: Path) -> None:
    load_count = verify_release_artifacts._load_expected_decision_count  # noqa: SLF001
    corpus_path = tmp_path / "corpus.json"
    with pytest.raises(ValueError, match="expected_decision_count must be > 0"):
        load_count(-1, corpus_path)

    invalid_payload = tmp_path / "invalid_payload.json"
    invalid_payload.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid corpus payload"):
        load_count(None, invalid_payload)

    non_list_cases = tmp_path / "non_list_cases.json"
    non_list_cases.write_text(json.dumps({"cases": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="corpus cases must be list"):
        load_count(None, non_list_cases)

    empty_cases = tmp_path / "empty_cases.json"
    empty_cases.write_text(json.dumps({"cases": ["bad"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="corpus has no cases"):
        load_count(None, empty_cases)

    invalid_utf8 = tmp_path / "invalid_utf8.json"
    invalid_utf8.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ValueError, match="corpus is not valid UTF-8"):
        load_count(None, invalid_utf8)


def test_verify_manifest_signature_error_branches() -> None:
    verify_signature = verify_release_artifacts._verify_manifest_signature  # noqa: SLF001
    bad_alg = {
        "signature_alg": "sha256",
        "signature": "hmac-sha256:abc",
        "decision_count": 1,
        "commit_sha": "abc",
    }
    bad_prefix = {
        "signature_alg": "hmac-sha256",
        "signature": "badprefix",
        "decision_count": 1,
        "commit_sha": "abc",
    }
    empty_digest = {
        "signature_alg": "hmac-sha256",
        "signature": "hmac-sha256:",
        "decision_count": 1,
        "commit_sha": "abc",
    }
    bad_alg_valid = verify_signature(bad_alg, "k")
    bad_prefix_valid = verify_signature(bad_prefix, "k")
    empty_digest_valid = verify_signature(empty_digest, "k")
    assert bad_alg_valid is False
    assert bad_prefix_valid is False
    assert empty_digest_valid is False


def test_format_text_result_includes_errors() -> None:
    result = verify_release_artifacts.ReleaseArtifactVerificationResult(
        passed=False,
        manifest_path="audit/security_manifest.json",
        expected_commit_sha="abc",
        observed_commit_sha="def",
        expected_decision_count=5,
        observed_decision_count=3,
        phase1_audit_line_count=2,
        signature_valid=False,
        errors=["boom"],
    )
    text = verify_release_artifacts._format_text_result(result)  # noqa: SLF001
    assert "release_artifacts passed=False" in text
    assert "- error: boom" in text


def test_run_release_artifact_verification_fails_when_phase1_audit_is_missing(
    tmp_path: Path,
) -> None:
    manifest, _ = _generate_valid_manifest(tmp_path, commit_sha="good-commit")
    missing_audit = tmp_path / "missing_phase1.jsonl"
    result = run_release_artifact_verification(
        manifest_path=manifest,
        phase1_audit_path=missing_audit,
        expected_commit_sha="good-commit",
        expected_decision_count=_attack_count(),
        attestation_key="gate-key",
    )
    assert result.passed is False
    assert any("audit file not found" in err for err in result.errors)


def test_main_returns_error_when_expected_commit_is_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    code = main(["--attestation-key", "gate-key"])
    captured = capsys.readouterr()
    assert code == 2
    assert "expected_commit_sha is required" in captured.err


def test_main_returns_error_when_attestation_key_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("AETHERYA_ATTESTATION_KEY", raising=False)
    code = main(
        [
            "--manifest-path",
            str(tmp_path / "missing.json"),
            "--expected-commit-sha",
            "abc",
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "attestation key is required" in captured.err


def test_main_json_mode_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest, phase1_audit = _generate_valid_manifest(tmp_path, commit_sha="main-commit")
    code = main(
        [
            "--manifest-path",
            str(manifest),
            "--phase1-audit-path",
            str(phase1_audit),
            "--expected-commit-sha",
            "main-commit",
            "--attestation-key",
            "gate-key",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert code == 0
    assert payload["passed"] is True
    assert payload["signature_valid"] is True


def test_main_text_mode_prints_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest, phase1_audit = _generate_valid_manifest(tmp_path, commit_sha="main-commit")
    code = main(
        [
            "--manifest-path",
            str(manifest),
            "--phase1-audit-path",
            str(phase1_audit),
            "--expected-commit-sha",
            "main-commit",
            "--attestation-key",
            "gate-key",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "release_artifacts passed=True" in captured.out
