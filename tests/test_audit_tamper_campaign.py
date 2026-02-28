from __future__ import annotations

import json
from pathlib import Path
from random import Random

from aetherya.audit import AuditLogger
from aetherya.audit_verify import verify_audit_file


def _read_events(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")


def _make_log(path: Path, *, total: int = 120, key: str = "campaign-key") -> None:
    logger = AuditLogger(path, attestation_key=key)
    for idx in range(total):
        logger.log(
            actor="campaign-bot",
            action=f"task-{idx}",
            decision={"allowed": True, "risk_score": idx % 7, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"trace-{idx}"},
        )


def _mutate_attestation(events: list[dict], rng: Random) -> None:
    idx = rng.randrange(len(events))
    events[idx]["attestation"] = "hmac-sha256:tampered"


def _mutate_swap_decision_ids(events: list[dict], rng: Random) -> None:
    a = rng.randrange(len(events))
    b = rng.randrange(len(events))
    if a == b:
        b = (b + 1) % len(events)
    events[a]["decision_id"], events[b]["decision_id"] = (
        events[b]["decision_id"],
        events[a]["decision_id"],
    )


def _mutate_reorder_window(events: list[dict], rng: Random) -> None:
    if len(events) < 6:
        return
    start = rng.randrange(0, len(events) - 5)
    end = start + rng.randrange(3, 6)
    events[start:end] = list(reversed(events[start:end]))


def _mutate_chain_fields(events: list[dict], rng: Random) -> None:
    idx = rng.randrange(len(events))
    events[idx]["prev_chain_hash"] = "sha256:deadbeef"


def test_tamper_campaign_reorder_only_breaks_causal_chain(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    _make_log(path, total=32, key="campaign-key")

    original = _read_events(path)
    reordered = list(reversed(original))
    _write_events(path, reordered)

    no_chain_records = verify_audit_file(path, require_hmac=True, attestation_key="campaign-key")
    chain_records = verify_audit_file(
        path,
        require_hmac=True,
        require_chain=True,
        attestation_key="campaign-key",
    )

    assert all(record.verification.valid for record in no_chain_records)
    assert any(not record.verification.valid for record in chain_records)
    chain_errors = [error for record in chain_records for error in record.verification.errors]
    assert any(error == "prev_chain_hash mismatch" for error in chain_errors)
    assert any(error == "chain_hash mismatch" for error in chain_errors)


def test_tamper_campaign_swap_decision_ids_detected_without_chain(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    _make_log(path, total=24, key="campaign-key")
    events = _read_events(path)
    events[5]["decision_id"], events[17]["decision_id"] = (
        events[17]["decision_id"],
        events[5]["decision_id"],
    )
    _write_events(path, events)

    records = verify_audit_file(path, require_hmac=True, attestation_key="campaign-key")

    invalid = [record for record in records if not record.verification.valid]
    assert len(invalid) == 2
    assert all("decision_id mismatch" in record.verification.errors for record in invalid)


def test_tamper_campaign_light_fuzzer_detects_multi_strategy_sabotage(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    _make_log(path, total=160, key="campaign-key")
    events = _read_events(path)

    rng = Random(1337)
    mutators = [
        _mutate_attestation,
        _mutate_swap_decision_ids,
        _mutate_reorder_window,
        _mutate_chain_fields,
    ]

    # deterministic baseline sabotage before fuzz rounds
    events[7]["decision_id"], events[119]["decision_id"] = (
        events[119]["decision_id"],
        events[7]["decision_id"],
    )
    events[40:45] = list(reversed(events[40:45]))
    events[90]["attestation"] = "hmac-sha256:tampered"

    for _ in range(18):
        mutator = mutators[rng.randrange(len(mutators))]
        mutator(events, rng)

    _write_events(path, events)
    records = verify_audit_file(
        path,
        require_hmac=True,
        require_chain=True,
        attestation_key="campaign-key",
    )

    invalid = [record for record in records if not record.verification.valid]
    all_errors = [error for record in invalid for error in record.verification.errors]

    assert invalid
    assert any(error == "decision_id mismatch" for error in all_errors)
    assert any(error == "attestation mismatch" for error in all_errors)
    assert any(error == "prev_chain_hash mismatch" for error in all_errors)
    assert any(error == "chain_hash mismatch" for error in all_errors)
