from __future__ import annotations

import json
from pathlib import Path

from aetherya.audit import AuditLogger
from aetherya.audit_verify import main, verify_audit_file


def _read_events(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")


def test_audit_integrity_stress_large_hmac_log_is_fully_valid(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="stress-key")

    for idx in range(300):
        logger.log(
            actor="stress-bot",
            action=f"action-{idx}",
            decision={"allowed": True, "risk_score": idx % 7, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"trace-{idx}"},
        )

    records = verify_audit_file(
        path,
        require_hmac=True,
        require_chain=True,
        attestation_key="stress-key",
    )

    assert len(records) == 300
    assert all(record.verification.valid for record in records)
    assert records[0].line_no == 1
    assert records[-1].line_no == 300


def test_audit_integrity_stress_detects_sparse_tampering(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="stress-key")

    for idx in range(420):
        logger.log(
            actor="stress-bot",
            action=f"operation-{idx}",
            decision={"allowed": True, "risk_score": idx % 5, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"ctx-{idx}", "stage": "stress"},
        )

    tampered_indices = {0, 57, 103, 199, 255, 311, 419}
    events = _read_events(path)
    for idx in tampered_indices:
        events[idx]["context"]["stage"] = "tampered"
    _write_events(path, events)

    records = verify_audit_file(path, require_hmac=True, attestation_key="stress-key")

    invalid_lines = {record.line_no for record in records if not record.verification.valid}
    assert invalid_lines == {idx + 1 for idx in tampered_indices}
    for record in records:
        if record.line_no not in invalid_lines:
            continue
        assert "context_hash mismatch" in record.verification.errors
        assert "decision_id mismatch" in record.verification.errors
        assert "attestation mismatch" in record.verification.errors


def test_audit_integrity_stress_cli_json_reports_exact_invalid_count(
    tmp_path: Path, capsys
) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="stress-key")

    for idx in range(180):
        logger.log(
            actor="stress-bot",
            action=f"job-{idx}",
            decision={"allowed": True, "risk_score": 0, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"job-{idx}"},
        )

    events = _read_events(path)
    for idx in range(0, 180, 15):
        events[idx]["attestation"] = "hmac-sha256:tampered"
    _write_events(path, events)

    code = main(
        [
            "--audit-path",
            str(path),
            "--attestation-key",
            "stress-key",
            "--require-hmac",
            "--json",
        ]
    )
    captured = capsys.readouterr()

    report = json.loads(captured.out.strip())
    assert code == 1
    assert report["total"] == 180
    assert report["invalid"] == 12
    assert report["valid"] == 168
    assert report["require_hmac"] is True
