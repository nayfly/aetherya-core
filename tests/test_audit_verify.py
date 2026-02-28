from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetherya.audit import AuditLogger, verify_audit_event
from aetherya.audit_verify import load_audit_events, main, select_event, verify_audit_file


def read_events(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def test_verify_audit_event_accepts_valid_sha256_event(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    event = read_events(path)[0]

    verification = verify_audit_event(event)

    assert verification.valid is True
    assert verification.errors == []
    assert verification.expected_attestation_alg == "sha256"


def test_verify_audit_event_accepts_valid_hmac_event_with_key(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    event = read_events(path)[0]

    verification = verify_audit_event(event, attestation_key="secret")

    assert verification.valid is True
    assert verification.errors == []
    assert verification.expected_attestation_alg == "hmac-sha256"


def test_verify_audit_event_uses_env_key_when_not_explicit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("AETHERYA_ATTESTATION_KEY", "env-secret")
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    event = read_events(path)[0]

    verification = verify_audit_event(event)

    assert verification.valid is True
    assert verification.expected_attestation_alg == "hmac-sha256"


def test_verify_audit_event_fails_with_wrong_key(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    event = read_events(path)[0]

    verification = verify_audit_event(event, attestation_key="wrong")

    assert verification.valid is False
    assert "attestation mismatch" in verification.errors


def test_verify_audit_event_detects_tampered_context(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    event = read_events(path)[0]
    event["context"]["mode"] = "operative"

    verification = verify_audit_event(event)

    assert verification.valid is False
    assert "context_hash mismatch" in verification.errors
    assert "decision_id mismatch" in verification.errors
    assert "attestation mismatch" in verification.errors


def test_verify_audit_event_detects_tampered_attestation_alg(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    event = read_events(path)[0]
    event["attestation_alg"] = "hmac-sha256"

    verification = verify_audit_event(event)

    assert verification.valid is False
    assert "attestation_alg mismatch" in verification.errors


def test_verify_audit_event_raises_on_non_dict() -> None:
    with pytest.raises(ValueError, match="event must be dict"):
        verify_audit_event([])  # type: ignore[arg-type]


def test_verify_audit_file_returns_line_numbers(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    logger.log(
        actor="robert",
        action="two",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    records = verify_audit_file(path)

    assert len(records) == 2
    assert records[0].line_no == 1
    assert records[1].line_no == 2
    assert all(record.verification.valid for record in records)


def test_verify_audit_file_supports_event_index(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    logger.log(
        actor="robert",
        action="two",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    records = verify_audit_file(path, event_index=-1)

    assert len(records) == 1
    assert records[0].line_no == 2
    assert records[0].verification.valid is True


def test_verify_audit_file_require_hmac_rejects_sha256_events(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    records = verify_audit_file(path, require_hmac=True)

    assert len(records) == 1
    assert records[0].verification.valid is False
    assert "require_hmac violation: attestation_alg=sha256" in records[0].verification.errors


def test_verify_audit_file_require_hmac_accepts_hmac_events(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    records = verify_audit_file(path, require_hmac=True, attestation_key="secret")

    assert len(records) == 1
    assert records[0].verification.valid is True


def test_verify_audit_file_require_chain_accepts_valid_order(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    for idx in range(4):
        logger.log(
            actor="robert",
            action=f"action-{idx}",
            decision={"allowed": True, "risk_score": idx, "state": "allow"},
            context={"mode": "consultive"},
        )

    records = verify_audit_file(
        path, require_chain=True, require_hmac=True, attestation_key="secret"
    )

    assert len(records) == 4
    assert all(record.verification.valid for record in records)


def test_verify_audit_file_require_chain_detects_reordered_events(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    for idx in range(5):
        logger.log(
            actor="robert",
            action=f"action-{idx}",
            decision={"allowed": True, "risk_score": idx, "state": "allow"},
            context={"mode": "consultive"},
        )
    events = read_events(path)
    events[1], events[3] = events[3], events[1]
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    records = verify_audit_file(
        path, require_chain=True, require_hmac=True, attestation_key="secret"
    )
    errors = [error for record in records for error in record.verification.errors]

    assert any("prev_chain_hash mismatch" == error for error in errors)
    assert any("chain_hash mismatch" == error for error in errors)


def test_verify_audit_file_require_chain_uses_full_scan_for_event_index(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    for idx in range(4):
        logger.log(
            actor="robert",
            action=f"action-{idx}",
            decision={"allowed": True, "risk_score": idx, "state": "allow"},
            context={"mode": "consultive"},
        )
    events = read_events(path)
    events[1], events[2] = events[2], events[1]
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    records = verify_audit_file(
        path,
        event_index=-1,
        require_chain=True,
        require_hmac=True,
        attestation_key="secret",
    )

    assert len(records) == 1
    assert records[0].line_no == 4
    assert records[0].verification.valid is False
    assert "prev_chain_hash mismatch" in records[0].verification.errors


def test_verify_audit_file_require_chain_rejects_missing_chain_fields(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    events = read_events(path)
    del events[0]["chain_hash"]
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    records = verify_audit_file(
        path, require_chain=True, require_hmac=True, attestation_key="secret"
    )

    assert len(records) == 1
    assert records[0].verification.valid is False
    assert "chain_hash mismatch" in records[0].verification.errors


def test_verify_audit_file_require_hmac_handles_missing_attestation_alg(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    events = read_events(path)
    del events[0]["attestation_alg"]
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    records = verify_audit_file(path, require_hmac=True)

    assert records[0].verification.valid is False
    assert "require_hmac violation: attestation_alg=-" in records[0].verification.errors


def test_verify_audit_file_raises_on_empty_audit(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("\n", encoding="utf-8")

    with pytest.raises(ValueError, match="audit contains no events"):
        verify_audit_file(path)


def test_verify_audit_file_raises_on_out_of_range_event_index(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    with pytest.raises(ValueError, match="event_index out of range: 3"):
        verify_audit_file(path, event_index=3)


def test_verify_audit_file_non_string_event_id_becomes_none(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    events = read_events(path)
    events[0]["event_id"] = 123
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    records = verify_audit_file(path)

    assert records[0].event_id is None
    assert records[0].verification.valid is True


def test_load_audit_events_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text('{"x":1\n', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON in audit at line 1"):
        load_audit_events(path)


def test_load_audit_events_rejects_non_object_payload(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("[1,2,3]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must be a JSON object"):
        load_audit_events(path)


def test_select_event_rejects_empty_events() -> None:
    with pytest.raises(ValueError, match="audit contains no events"):
        select_event([], 0)


def test_main_returns_zero_for_valid_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    code = main(["--audit-path", str(path)])
    captured = capsys.readouterr()

    assert code == 0
    assert "total=1" in captured.out
    assert captured.err == ""


def test_main_returns_one_for_invalid_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    events = read_events(path)
    events[0]["attestation"] = "sha256:tampered"
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    code = main(["--audit-path", str(path)])
    captured = capsys.readouterr()

    assert code == 1
    assert "invalid line=1" in captured.out
    assert captured.err == ""


def test_main_json_mode_emits_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    code = main(["--audit-path", str(path), "--event-index", "-1", "--json"])
    captured = capsys.readouterr()

    payload = json.loads(captured.out.strip())
    assert code == 0
    assert payload["total"] == 1
    assert payload["valid"] == 1
    assert payload["invalid"] == 0
    assert payload["require_hmac"] is False
    assert payload["require_chain"] is False
    assert payload["results"][0]["line_no"] == 1


def test_main_require_hmac_rejects_sha256_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    code = main(["--audit-path", str(path), "--require-hmac"])
    captured = capsys.readouterr()

    assert code == 1
    assert "require_hmac violation" in captured.out
    assert captured.err == ""


def test_main_require_hmac_accepts_hmac_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    code = main(
        [
            "--audit-path",
            str(path),
            "--attestation-key",
            "secret",
            "--require-hmac",
            "--json",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out.strip())
    assert code == 0
    assert payload["require_hmac"] is True
    assert payload["require_chain"] is False
    assert payload["invalid"] == 0
    assert captured.err == ""


def test_main_require_chain_rejects_reordered_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    for idx in range(4):
        logger.log(
            actor="robert",
            action=f"action-{idx}",
            decision={"allowed": True, "risk_score": idx, "state": "allow"},
            context={"mode": "consultive"},
        )
    events = read_events(path)
    events.reverse()
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    code = main(
        [
            "--audit-path",
            str(path),
            "--attestation-key",
            "secret",
            "--require-hmac",
            "--require-chain",
            "--json",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out.strip())
    assert code == 1
    assert payload["require_hmac"] is True
    assert payload["require_chain"] is True
    assert payload["invalid"] > 0


def test_main_returns_error_for_missing_audit(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--audit-path", "missing.jsonl"])
    captured = capsys.readouterr()

    assert code == 2
    assert "error: audit file not found" in captured.err
