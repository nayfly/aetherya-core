from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aetherya.audit import AuditVerification, materialize_chain_hash, verify_audit_event


@dataclass(frozen=True)
class AuditVerificationRecord:
    line_no: int
    event_id: str | None
    verification: AuditVerification


def load_audit_events(path: str | Path) -> list[dict[str, Any]]:
    audit_path = Path(path)
    if not audit_path.exists():
        raise ValueError(f"audit file not found: {audit_path}")

    events: list[dict[str, Any]] = []
    for idx, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in audit at line {idx + 1}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"audit event at line {idx + 1} must be a JSON object")
        events.append(payload)
    return events


def select_event(events: list[dict[str, Any]], event_index: int) -> tuple[int, dict[str, Any]]:
    if not events:
        raise ValueError("audit contains no events")
    try:
        event = events[event_index]
    except IndexError as exc:
        raise ValueError(f"event_index out of range: {event_index}") from exc

    normalized_index = event_index if event_index >= 0 else len(events) + event_index
    return normalized_index, event


def verify_audit_file(
    path: str | Path,
    *,
    event_index: int | None = None,
    attestation_key: str | None = None,
    require_hmac: bool = False,
    require_chain: bool = False,
) -> list[AuditVerificationRecord]:
    events = load_audit_events(path)
    if not events:
        raise ValueError("audit contains no events")

    selected_index: int | None = None
    if event_index is not None:
        selected_index, _ = select_event(events, event_index)
        if not require_chain:
            event = events[selected_index]
            verification = verify_audit_event(event, attestation_key=attestation_key)
            verification = _apply_require_hmac(verification, event=event, require_hmac=require_hmac)
            return [
                AuditVerificationRecord(
                    line_no=selected_index + 1,
                    event_id=_event_id(event),
                    verification=verification,
                )
            ]

    records: list[AuditVerificationRecord] = []
    expected_chain_tip: str | None = None
    for idx, event in enumerate(events):
        verification = verify_audit_event(event, attestation_key=attestation_key)
        verification = _apply_require_hmac(verification, event=event, require_hmac=require_hmac)
        verification, expected_chain_tip = _apply_require_chain(
            verification=verification,
            event=event,
            expected_prev_chain_hash=expected_chain_tip,
            require_chain=require_chain,
        )
        if selected_index is None or idx == selected_index:
            records.append(
                AuditVerificationRecord(
                    line_no=idx + 1,
                    event_id=_event_id(event),
                    verification=verification,
                )
            )

    return records


def _event_id(event: dict[str, Any]) -> str | None:
    raw = event.get("event_id")
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    return cleaned if cleaned else None


def _apply_require_hmac(
    verification: AuditVerification, *, event: dict[str, Any], require_hmac: bool
) -> AuditVerification:
    if not require_hmac:
        return verification

    attestation_alg = str(event.get("attestation_alg", "")).strip()
    if attestation_alg == "hmac-sha256":
        return verification

    errors = list(verification.errors)
    errors.append(f"require_hmac violation: attestation_alg={attestation_alg or '-'}")
    return AuditVerification(
        valid=False,
        errors=errors,
        expected_context_hash=verification.expected_context_hash,
        expected_decision_id=verification.expected_decision_id,
        expected_attestation_alg=verification.expected_attestation_alg,
        expected_attestation=verification.expected_attestation,
    )


def _clean_hash(value: Any) -> str | None:
    cleaned = value.strip() if isinstance(value, str) else ""
    return cleaned if cleaned else None


def _apply_require_chain(
    *,
    verification: AuditVerification,
    event: dict[str, Any],
    expected_prev_chain_hash: str | None,
    require_chain: bool,
) -> tuple[AuditVerification, str | None]:
    if not require_chain:
        return verification, None

    expected_chain_hash = materialize_chain_hash(
        prev_chain_hash=expected_prev_chain_hash,
        decision_id=str(event.get("decision_id", "")),
        context_hash=str(event.get("context_hash", "")),
        attestation=str(event.get("attestation", "")),
        actor=event.get("actor"),
        action=event.get("action"),
        ts=str(event.get("ts", "")),
    )
    actual_prev_chain_hash = _clean_hash(event.get("prev_chain_hash"))
    actual_chain_hash = _clean_hash(event.get("chain_hash"))

    errors = list(verification.errors)
    if actual_prev_chain_hash != expected_prev_chain_hash:
        errors.append("prev_chain_hash mismatch")
    if actual_chain_hash != expected_chain_hash:
        errors.append("chain_hash mismatch")

    if not errors:
        return verification, expected_chain_hash

    return (
        AuditVerification(
            valid=False,
            errors=errors,
            expected_context_hash=verification.expected_context_hash,
            expected_decision_id=verification.expected_decision_id,
            expected_attestation_alg=verification.expected_attestation_alg,
            expected_attestation=verification.expected_attestation,
        ),
        expected_chain_hash,
    )


def _build_report(
    *,
    records: list[AuditVerificationRecord],
    audit_path: str | Path,
    event_index: int | None,
    require_hmac: bool,
    require_chain: bool,
) -> dict[str, Any]:
    valid_count = sum(1 for record in records if record.verification.valid)
    invalid_count = len(records) - valid_count
    return {
        "audit_path": str(audit_path),
        "event_index": event_index,
        "require_hmac": require_hmac,
        "require_chain": require_chain,
        "total": len(records),
        "valid": valid_count,
        "invalid": invalid_count,
        "results": [
            {
                "line_no": record.line_no,
                "event_id": record.event_id,
                "valid": record.verification.valid,
                "errors": list(record.verification.errors),
            }
            for record in records
        ],
    }


def _print_text_report(report: dict[str, Any]) -> None:
    print(
        f"verified events: total={report['total']} valid={report['valid']} invalid={report['invalid']}"
    )
    for item in report["results"]:
        if item["valid"]:
            continue
        event_id = item["event_id"] or "-"
        errors = "; ".join(str(error) for error in item["errors"]) if item["errors"] else "unknown"
        print(f"invalid line={item['line_no']} event_id={event_id} errors={errors}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify integrity and attestation for AETHERYA audit JSONL events."
    )
    parser.add_argument(
        "--audit-path",
        default="audit/decisions.jsonl",
        help="Path to audit decisions JSONL",
    )
    parser.add_argument(
        "--event-index",
        type=int,
        default=None,
        help="Optional single event index (supports negative index).",
    )
    parser.add_argument(
        "--attestation-key",
        default=None,
        help="Optional attestation key. If omitted, env AETHERYA_ATTESTATION_KEY is used.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON report.",
    )
    parser.add_argument(
        "--require-hmac",
        action="store_true",
        help="Reject events not signed with hmac-sha256.",
    )
    parser.add_argument(
        "--require-chain",
        action="store_true",
        help="Validate chain causality via prev_chain_hash/chain_hash.",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        records = verify_audit_file(
            args.audit_path,
            event_index=args.event_index,
            attestation_key=args.attestation_key,
            require_hmac=args.require_hmac,
            require_chain=args.require_chain,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = _build_report(
        records=records,
        audit_path=args.audit_path,
        event_index=args.event_index,
        require_hmac=args.require_hmac,
        require_chain=args.require_chain,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        _print_text_report(report)

    return 0 if report["invalid"] == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
