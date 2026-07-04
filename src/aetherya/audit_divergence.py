from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from aetherya.audit_verify import load_audit_events

_ACTION_PREVIEW_MAX_CHARS = 80


@dataclass(frozen=True)
class DivergenceRecord:
    """One audit event where the LLM shadow produced an ethical evaluation."""

    line_no: int
    event_id: str | None
    actor: str | None
    action: str | None
    provider: str | None
    dry_run: bool | None
    core_state: str | None
    core_risk_score: int | None
    suggested_state: str | None
    suggested_risk_score: int | None
    risk_delta: int
    absolute_risk_delta: int
    state_mismatch: bool
    parse_success: bool | None
    flags: tuple[str, ...]


def _clean_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned if cleaned else None


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def extract_divergence_records(
    events: list[dict[str, Any]],
) -> tuple[list[DivergenceRecord], int]:
    """
    Extract shadow divergence data from audit events.

    Returns (records, shadow_error_count). Events without an llm_shadow block are
    skipped; shadow blocks without ethical_divergence (provider errors/timeouts)
    are counted as shadow errors.
    """
    records: list[DivergenceRecord] = []
    shadow_errors = 0
    for idx, event in enumerate(events):
        context = event.get("context")
        if not isinstance(context, dict):
            continue
        shadow = context.get("llm_shadow")
        if not isinstance(shadow, dict):
            continue
        divergence = shadow.get("ethical_divergence")
        if not isinstance(divergence, dict):
            shadow_errors += 1
            continue

        suggestion_raw = shadow.get("shadow_suggestion")
        suggestion = suggestion_raw if isinstance(suggestion_raw, dict) else {}
        evaluation_raw = shadow.get("evaluation")
        evaluation = evaluation_raw if isinstance(evaluation_raw, dict) else {}
        decision_raw = event.get("decision")
        decision = decision_raw if isinstance(decision_raw, dict) else {}

        parse_raw = evaluation.get("parse_success")
        flags_raw = evaluation.get("flags", [])
        risk_delta = _safe_int(divergence.get("risk_delta")) or 0

        records.append(
            DivergenceRecord(
                line_no=idx + 1,
                event_id=_clean_str(event.get("event_id")),
                actor=_clean_str(event.get("actor")),
                action=_clean_str(event.get("action")),
                provider=_clean_str(shadow.get("provider")),
                dry_run=bool(shadow["dry_run"]) if "dry_run" in shadow else None,
                core_state=_clean_str(decision.get("state")),
                core_risk_score=_safe_int(decision.get("risk_score")),
                suggested_state=_clean_str(suggestion.get("suggested_state")),
                suggested_risk_score=_safe_int(suggestion.get("suggested_risk_score")),
                risk_delta=risk_delta,
                absolute_risk_delta=_safe_int(divergence.get("absolute_risk_delta"))
                or abs(risk_delta),
                state_mismatch=bool(divergence.get("state_mismatch", False)),
                parse_success=bool(parse_raw) if parse_raw is not None else None,
                flags=(
                    tuple(str(flag) for flag in flags_raw if isinstance(flag, str))
                    if isinstance(flags_raw, list)
                    else ()
                ),
            )
        )
    return records, shadow_errors


def _round_rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def _action_preview(action: str | None) -> str | None:
    if action is None:
        return None
    if len(action) <= _ACTION_PREVIEW_MAX_CHARS:
        return action
    return action[:_ACTION_PREVIEW_MAX_CHARS] + "..."


def build_divergence_report(
    records: list[DivergenceRecord],
    *,
    audit_path: str,
    events_total: int,
    shadow_errors: int,
    top: int,
    min_abs_delta: int,
) -> dict[str, Any]:
    mismatches = sum(1 for record in records if record.state_mismatch)
    parse_known = [record for record in records if record.parse_success is not None]
    parse_ok = sum(1 for record in parse_known if record.parse_success)

    deltas = [record.risk_delta for record in records]
    abs_deltas = [record.absolute_risk_delta for record in records]
    flag_counts: Counter[str] = Counter()
    for record in records:
        flag_counts.update(record.flags)

    top_records = sorted(
        (record for record in records if record.absolute_risk_delta >= min_abs_delta),
        key=lambda record: (record.absolute_risk_delta, record.line_no),
        reverse=True,
    )[: max(0, top)]

    return {
        "audit_path": audit_path,
        "events_total": events_total,
        "shadow_evaluations": len(records),
        "shadow_errors": shadow_errors,
        "state_mismatches": mismatches,
        "state_mismatch_rate": _round_rate(mismatches, len(records)),
        "risk_delta": {
            "mean": round(sum(deltas) / len(deltas), 4) if deltas else 0.0,
            "mean_absolute": round(sum(abs_deltas) / len(abs_deltas), 4) if abs_deltas else 0.0,
            "max_absolute": max(abs_deltas) if abs_deltas else 0,
        },
        "parse": {
            "evaluated": len(parse_known),
            "success": parse_ok,
            "success_rate": _round_rate(parse_ok, len(parse_known)),
        },
        "flags": dict(sorted(flag_counts.items())),
        "top_divergences": [
            {
                "line_no": record.line_no,
                "event_id": record.event_id,
                "actor": record.actor,
                "action": _action_preview(record.action),
                "provider": record.provider,
                "dry_run": record.dry_run,
                "core_state": record.core_state,
                "core_risk_score": record.core_risk_score,
                "suggested_state": record.suggested_state,
                "suggested_risk_score": record.suggested_risk_score,
                "risk_delta": record.risk_delta,
                "absolute_risk_delta": record.absolute_risk_delta,
                "state_mismatch": record.state_mismatch,
                "parse_success": record.parse_success,
                "flags": list(record.flags),
            }
            for record in top_records
        ],
    }


def _print_text_report(report: dict[str, Any]) -> None:
    print(
        "events={events} shadow_evaluations={evals} shadow_errors={errors}".format(
            events=report["events_total"],
            evals=report["shadow_evaluations"],
            errors=report["shadow_errors"],
        )
    )
    print(
        "state_mismatches={mismatches} mismatch_rate={rate}".format(
            mismatches=report["state_mismatches"],
            rate=report["state_mismatch_rate"],
        )
    )
    delta = report["risk_delta"]
    print(
        "risk_delta mean={mean} mean_abs={mean_abs} max_abs={max_abs}".format(
            mean=delta["mean"],
            mean_abs=delta["mean_absolute"],
            max_abs=delta["max_absolute"],
        )
    )
    parse = report["parse"]
    print(
        "parse evaluated={evaluated} success={success} success_rate={rate}".format(
            evaluated=parse["evaluated"],
            success=parse["success"],
            rate=parse["success_rate"],
        )
    )
    if report["flags"]:
        rendered = " ".join(f"{name}={count}" for name, count in report["flags"].items())
        print(f"flags {rendered}")
    for item in report["top_divergences"]:
        print(
            "divergence line={line} event_id={event_id} abs_delta={abs_delta} "
            "core={core_state}/{core_risk} shadow={sug_state}/{sug_risk} mismatch={mismatch}".format(
                line=item["line_no"],
                event_id=item["event_id"] or "-",
                abs_delta=item["absolute_risk_delta"],
                core_state=item["core_state"] or "-",
                core_risk=item["core_risk_score"] if item["core_risk_score"] is not None else "-",
                sug_state=item["suggested_state"] or "-",
                sug_risk=(
                    item["suggested_risk_score"]
                    if item["suggested_risk_score"] is not None
                    else "-"
                ),
                mismatch=item["state_mismatch"],
            )
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate LLM-shadow ethical divergence telemetry from AETHERYA audit JSONL events."
        )
    )
    parser.add_argument(
        "--audit-path",
        default="audit/decisions.jsonl",
        help="Path to audit decisions JSONL",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of highest-divergence events to include (default 5).",
    )
    parser.add_argument(
        "--min-abs-delta",
        type=int,
        default=0,
        help="Only include events with absolute_risk_delta >= this value in the top list.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON report.",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        events = load_audit_events(args.audit_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    records, shadow_errors = extract_divergence_records(events)
    report = build_divergence_report(
        records,
        audit_path=str(args.audit_path),
        events_total=len(events),
        shadow_errors=shadow_errors,
        top=args.top,
        min_abs_delta=args.min_abs_delta,
    )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        _print_text_report(report)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
