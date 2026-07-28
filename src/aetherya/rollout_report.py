from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from aetherya.audit_verify import verify_audit_file
from aetherya.enforcement import PHASES, resolve_phase
from aetherya.review_store import FALSE_POSITIVE, ReviewStore

# ---------------------------------------------------------------------------
# Phase-1 measurement.
#
# The rollout plan says "review every hard_deny event and confirm it is a true
# positive" and "at least 2 weeks or 10 000 decisions". Without tooling that is
# a grep and a guess, so nobody does it and the phase gate becomes a formality.
# This reads the audit trail and answers the exit criteria directly, including
# printing the hard_deny events that need human eyes on them.
#
# See docs/rollout-phases.md.
# ---------------------------------------------------------------------------

DEFAULT_MIN_DECISIONS = 10_000
DEFAULT_MIN_DAYS = 14.0


@dataclass
class Criterion:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class RolloutReport:
    audit_path: str
    current_phase: int
    total_decisions: int = 0
    window_days: float = 0.0
    first_event: str | None = None
    last_event: str | None = None
    states: dict[str, int] = field(default_factory=dict)
    would_block_next_phase: int = 0
    actors_by_state: dict[str, list[str]] = field(default_factory=dict)
    tools_by_state: dict[str, list[str]] = field(default_factory=dict)
    intent_escalations: int = 0
    semantic_skipped: int = 0
    policy_fingerprints: list[str] = field(default_factory=list)
    chain_valid: bool = False
    chain_errors: int = 0
    chain_error_detail: str | None = None
    hard_deny_events: list[dict[str, Any]] = field(default_factory=list)
    criteria: list[Criterion] = field(default_factory=list)

    @property
    def ready_to_advance(self) -> bool:
        return bool(self.criteria) and all(c.passed for c in self.criteria)

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_path": self.audit_path,
            "current_phase": self.current_phase,
            "next_phase": min(self.current_phase + 1, max(PHASES)),
            "ready_to_advance": self.ready_to_advance,
            "window": {
                "total_decisions": self.total_decisions,
                "days": round(self.window_days, 2),
                "first_event": self.first_event,
                "last_event": self.last_event,
            },
            "states": self.states,
            "would_block_next_phase": self.would_block_next_phase,
            "actors_by_state": self.actors_by_state,
            "tools_by_state": self.tools_by_state,
            "intent_escalations": self.intent_escalations,
            "semantic_skipped": self.semantic_skipped,
            "policy_fingerprints": self.policy_fingerprints,
            "chain": {
                "valid": self.chain_valid,
                "errors": self.chain_errors,
                "detail": self.chain_error_detail,
            },
            "hard_deny_events": self.hard_deny_events,
            "criteria": [c.to_dict() for c in self.criteria],
        }


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise ValueError(f"audit file not found: {path}")
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def build_report(
    audit_path: str | Path,
    *,
    current_phase: int = 1,
    min_decisions: int = DEFAULT_MIN_DECISIONS,
    min_days: float = DEFAULT_MIN_DAYS,
    max_hard_deny_samples: int = 50,
    review_path: str | Path | None = None,
) -> RolloutReport:
    path = Path(audit_path)
    phase = resolve_phase(current_phase)
    next_phase = PHASES[min(current_phase + 1, max(PHASES))]
    events = _load_events(path)
    recorded_reviews = ReviewStore(review_path).reviews() if review_path is not None else {}

    report = RolloutReport(audit_path=str(path), current_phase=phase.number)
    report.total_decisions = len(events)

    states: Counter[str] = Counter()
    actors: dict[str, set[str]] = {}
    tools: dict[str, set[str]] = {}
    fingerprints: set[str] = set()
    timestamps: list[datetime] = []

    for event in events:
        decision = event.get("decision") or {}
        context = event.get("context") or {}
        state = str(decision.get("state", "unknown"))
        states[state] += 1

        actors.setdefault(state, set()).add(str(event.get("actor", "unknown")))
        action_ctx = context.get("action") if isinstance(context.get("action"), dict) else {}
        tool = action_ctx.get("tool") if isinstance(action_ctx, dict) else None
        tools.setdefault(state, set()).add(str(tool) if tool else "-")

        if context.get("intent_escalation"):
            report.intent_escalations += 1
        constitution = context.get("constitution")
        if isinstance(constitution, dict) and constitution.get("semantic_skipped"):
            report.semantic_skipped += 1

        fingerprint = context.get("policy_fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            fingerprints.add(fingerprint)

        ts = _parse_ts(event.get("ts"))
        if ts is not None:
            timestamps.append(ts)

        # Every hard_deny needs human eyes before enforcement is switched on.
        # `event_id` is what a recorded verdict hangs off, so it travels with
        # the sample rather than being looked up again later.
        if state == "hard_deny" and len(report.hard_deny_events) < max_hard_deny_samples:
            event_id = str(event.get("event_id", ""))
            review = recorded_reviews.get(event_id)
            report.hard_deny_events.append(
                {
                    "event_id": event_id,
                    "ts": event.get("ts"),
                    "actor": event.get("actor"),
                    "action": str(event.get("action", ""))[:160],
                    "reason": decision.get("reason"),
                    "risk_score": decision.get("risk_score"),
                    "review": review.to_dict() if review is not None else None,
                }
            )

    report.states = dict(sorted(states.items()))
    report.actors_by_state = {k: sorted(v) for k, v in sorted(actors.items())}
    report.tools_by_state = {k: sorted(v) for k, v in sorted(tools.items())}
    report.policy_fingerprints = sorted(fingerprints)
    report.would_block_next_phase = sum(
        states[s] for s in (next_phase.blocks | next_phase.confirms) if s in states
    )

    if timestamps:
        timestamps.sort()
        report.first_event = timestamps[0].isoformat()
        report.last_event = timestamps[-1].isoformat()
        report.window_days = (timestamps[-1] - timestamps[0]).total_seconds() / 86400.0

    # A malformed line or an empty file makes `verify_audit_file` raise. Both are
    # findings an operator must see before advancing a phase — not reasons for
    # the report to crash, and certainly not something to skip silently.
    try:
        verification = verify_audit_file(str(path), require_chain=True)
        report.chain_errors = sum(1 for r in verification if not r.verification.valid)
        report.chain_valid = report.chain_errors == 0
    except ValueError as exc:
        report.chain_valid = False
        report.chain_error_detail = str(exc)

    report.criteria = _evaluate_criteria(report, min_decisions=min_decisions, min_days=min_days)
    return report


def _evaluate_criteria(
    report: RolloutReport, *, min_decisions: int, min_days: float
) -> list[Criterion]:
    volume_ok = report.total_decisions >= min_decisions or report.window_days >= min_days
    criteria = [
        Criterion(
            name="sufficient_window",
            passed=volume_ok,
            detail=(
                f"{report.total_decisions} decisions over {report.window_days:.1f} days "
                f"(need {min_decisions} or {min_days:.0f} days)"
            ),
        ),
        Criterion(
            name="chain_intact",
            passed=report.chain_valid,
            detail=(
                "audit chain verifies clean"
                if report.chain_valid
                else (report.chain_error_detail or f"{report.chain_errors} invalid event(s)")
                + " — investigate before advancing"
            ),
        ),
        Criterion(
            name="single_policy",
            passed=len(report.policy_fingerprints) <= 1,
            detail=(
                f"{len(report.policy_fingerprints)} distinct policy fingerprint(s); more than "
                "one means the window mixes different engines and must be restarted"
            ),
        ),
        _hard_deny_reviewed(report),
    ]
    return criteria


def _hard_deny_reviewed(report: RolloutReport) -> Criterion:
    """
    Never auto-passes: it passes only on verdicts a human recorded.

    The tool can count hard_deny events and show them; it cannot judge them.
    What it can do is check that someone did — and refuse to advance while any
    of them is unreviewed or was judged a false positive.
    """
    total = report.states.get("hard_deny", 0)
    if total == 0:
        return Criterion(
            name="hard_deny_reviewed",
            passed=True,
            detail="no hard_deny events in this window",
        )

    unreviewed = [e for e in report.hard_deny_events if e.get("review") is None]
    false_positives = [
        e
        for e in report.hard_deny_events
        if isinstance(e.get("review"), dict) and e["review"].get("verdict") == FALSE_POSITIVE
    ]

    # A false positive is the finding phase 1 exists to produce. It blocks the
    # advance because enforcing a rule a human already called wrong is exactly
    # the outcome this phase is meant to prevent.
    if false_positives:
        return Criterion(
            name="hard_deny_reviewed",
            passed=False,
            detail=(
                f"{len(false_positives)} of {total} hard_deny event(s) were judged FALSE "
                "positives — fix the rule and restart the window, do not advance "
                "(see docs/rollout-phases.md#phase-1--shadow)"
            ),
        )

    # `hard_deny_events` is capped by max_hard_deny_samples. If the window holds
    # more than we sampled, the ones we never showed cannot have been reviewed.
    unsampled = total - len(report.hard_deny_events)
    outstanding = len(unreviewed) + max(unsampled, 0)
    if outstanding:
        return Criterion(
            name="hard_deny_reviewed",
            passed=False,
            detail=(
                f"{outstanding} of {total} hard_deny event(s) still require manual review "
                "— confirm every one is a true positive, then advance"
            ),
        )

    reviewers = sorted({e["review"]["reviewer"] for e in report.hard_deny_events})
    return Criterion(
        name="hard_deny_reviewed",
        passed=True,
        detail=f"all {total} hard_deny event(s) reviewed and confirmed by {', '.join(reviewers)}",
    )


def _print_text(report: RolloutReport) -> None:
    phase = resolve_phase(report.current_phase)
    nxt = PHASES[min(report.current_phase + 1, max(PHASES))]

    print(f"\n  ROLLOUT REPORT — phase {phase.number} ({phase.name})")
    print(f"  {report.audit_path}")
    print("  " + "─" * 68)

    print(f"\n  window       {report.total_decisions} decisions over {report.window_days:.1f} days")
    if report.first_event:
        print(f"               {report.first_event}  ->  {report.last_event}")

    print("\n  decisions by state")
    for state, count in report.states.items():
        share = (count / report.total_decisions * 100) if report.total_decisions else 0.0
        actors = ", ".join(report.actors_by_state.get(state, [])[:4])
        print(f"    {state:12} {count:6}  {share:5.1f}%   actors: {actors}")

    print(
        f"\n  phase {nxt.number} ({nxt.name}) would act on {report.would_block_next_phase} of these"
    )
    print(f"  intent escalations   {report.intent_escalations}")
    print(f"  semantic skipped     {report.semantic_skipped}")
    print(f"  policy fingerprints  {len(report.policy_fingerprints)}")
    print(f"  audit chain          {'intact' if report.chain_valid else 'INVALID'}")

    if report.hard_deny_events:
        print(f"\n  hard_deny events to review ({len(report.hard_deny_events)} shown)")
        for event in report.hard_deny_events[:10]:
            print(f"    {event['ts']}  {event['actor']}")
            print(f"      {event['action']}")
            print(f"      -> {event['reason']}")

    print("\n  exit criteria")
    for criterion in report.criteria:
        mark = "ok " if criterion.passed else "-- "
        print(f"    {mark} {criterion.name}: {criterion.detail}")

    verdict = "READY" if report.ready_to_advance else "NOT READY"
    print(f"\n  {verdict} to advance to phase {nxt.number}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure a rollout phase against its exit criteria."
    )
    parser.add_argument("--audit-path", default="audit/decisions.jsonl")
    parser.add_argument("--phase", type=int, default=1, choices=sorted(PHASES))
    parser.add_argument("--min-decisions", type=int, default=DEFAULT_MIN_DECISIONS)
    parser.add_argument("--min-days", type=float, default=DEFAULT_MIN_DAYS)
    parser.add_argument(
        "--review-path",
        default="audit/reviews.jsonl",
        help="Human verdicts on hard_deny events, as recorded by the operator console.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args(argv)

    try:
        report = build_report(
            args.audit_path,
            current_phase=int(args.phase),
            min_decisions=int(args.min_decisions),
            min_days=float(args.min_days),
            review_path=args.review_path,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str))
    else:
        _print_text(report)

    # Exit 1 when not ready: usable as a gate in a promotion pipeline.
    return 0 if report.ready_to_advance else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
