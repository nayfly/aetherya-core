from __future__ import annotations

import json
from pathlib import Path
from random import Random

import aetherya.verify_release_artifacts as verify_release_artifacts
from aetherya.security_gate import run_security_gate
from aetherya.verify_release_artifacts import run_release_artifact_verification

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "security_corpus" / "v1"


def _generate_valid_artifacts(tmp_path: Path, commit_sha: str) -> tuple[Path, Path]:
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


def _attack_count() -> int:
    payload = json.loads((_FIXTURE_DIR / "jailbreak_attacks.json").read_text(encoding="utf-8"))
    return len(payload["cases"])


def _round_mutate_manifest(path: Path, rng: Random, round_id: int) -> None:
    strategy = round_id % 6
    if strategy == 0:
        path.write_bytes(b"\xff\xfe\x00corrupted")
        return
    if strategy == 1:
        path.write_text("{broken-json", encoding="utf-8")
        return

    payload = json.loads(path.read_text(encoding="utf-8"))
    if strategy == 2:
        payload["signature"] = "hmac-sha256:tampered"
    elif strategy == 3:
        payload["commit_sha"] = f"mismatch-{rng.randrange(10_000)}"
    elif strategy == 4:
        payload["decision_count"] = int(payload.get("decision_count", 0)) + 1
    else:
        payload.pop("signature", None)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _round_mutate_phase1_audit(path: Path, rng: Random, round_id: int) -> None:
    strategy = round_id % 4
    if strategy == 0:
        path.write_bytes(b"\xff\xff\xff")
        return
    if strategy == 1:
        path.write_text("\n", encoding="utf-8")
        return
    if strategy == 2:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            cut = max(1, len(lines) // 2)
            path.write_text("\n".join(lines[:cut]) + "\n", encoding="utf-8")
        return

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if lines:
        idx = rng.randrange(len(lines))
        lines[idx] = "{not-json-line"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_release_artifact_fuzz_campaign_detects_corruption_in_all_rounds(tmp_path: Path) -> None:
    commit_sha = "fuzz-commit"
    manifest, phase1_audit = _generate_valid_artifacts(tmp_path, commit_sha=commit_sha)
    baseline_manifest = manifest.read_bytes()
    baseline_phase1 = phase1_audit.read_bytes()

    rng = Random(1337)
    rounds = 64
    detected_failures = 0
    for round_id in range(rounds):
        manifest.write_bytes(baseline_manifest)
        phase1_audit.write_bytes(baseline_phase1)

        if round_id % 2 == 0:
            _round_mutate_manifest(manifest, rng, round_id)
        else:
            _round_mutate_phase1_audit(phase1_audit, rng, round_id)

        result = run_release_artifact_verification(
            manifest_path=manifest,
            phase1_audit_path=phase1_audit,
            expected_commit_sha=commit_sha,
            expected_decision_count=_attack_count(),
            attestation_key="gate-key",
        )
        if not result.passed:
            detected_failures += 1

    assert detected_failures == rounds


def test_count_jsonl_events_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad_utf8.jsonl"
    path.write_bytes(b"\xff\xfe\x00")
    try:
        verify_release_artifacts._count_jsonl_events(path)  # noqa: SLF001
    except ValueError as exc:
        assert "not valid UTF-8" in str(exc)
    else:
        raise AssertionError("expected ValueError for invalid UTF-8")


def test_count_jsonl_events_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text('\n{"event_id":"ok"}\n\n', encoding="utf-8")
    count = verify_release_artifacts._count_jsonl_events(path)  # noqa: SLF001
    assert count == 1


def test_count_jsonl_events_rejects_non_object_line(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("[1,2,3]\n", encoding="utf-8")
    try:
        verify_release_artifacts._count_jsonl_events(path)  # noqa: SLF001
    except ValueError as exc:
        assert "must be a JSON object" in str(exc)
    else:
        raise AssertionError("expected ValueError for non-object JSON line")
