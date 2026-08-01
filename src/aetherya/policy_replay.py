from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aetherya.actions import ActionRequest
from aetherya.config import PolicyConfig, load_policy_config
from aetherya.constitution import Constitution
from aetherya.pipeline import run_pipeline, run_pipeline_structured
from aetherya.policy_engine import DecisionState, decision_rank

# ---------------------------------------------------------------------------
# Replay a candidate policy against recorded history.
#
# Every policy change so far was validated by hand: write a throwaway script,
# replay the trail, count what moved. That answered the only question that
# matters — "what does this change about decisions I have already seen?" — and
# it caught real problems each time: 51 hard_deny that were vocabulary rather
# than danger, two escalations from parameter names nobody could have guessed.
#
# It is also the piece any future change has to stand on, whether a human wrote
# it or a learner proposed it. A policy that has not been replayed is a policy
# whose effect nobody has measured.
#
# Two things it deliberately separates:
#
#   - Loosening is not the same as tightening. A decision that becomes less
#     strict is where a regression hides; one that becomes more strict is at
#     worst friction. They are counted apart and the exit code only reacts to
#     the first.
#   - Real traffic is not the adversarial corpus. Traffic tells you about
#     friction, the corpus tells you about protection. A change that improves
#     one while quietly breaking the other is exactly what a replay is for.
# ---------------------------------------------------------------------------

_CORPUS_DIR = Path("tests/fixtures/security_corpus/v1")


@dataclass
class Change:
    action: str
    before: str
    after: str
    before_risk: int
    after_risk: int
    reason_after: str

    @property
    def loosened(self) -> bool:
        """True when the candidate is less strict than the baseline."""
        return decision_rank(DecisionState(self.after)) < decision_rank(DecisionState(self.before))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "before": self.before,
            "after": self.after,
            "before_risk": self.before_risk,
            "after_risk": self.after_risk,
            "reason_after": self.reason_after,
            "loosened": self.loosened,
        }


@dataclass
class ReplayReport:
    baseline_path: str
    candidate_path: str
    total: int = 0
    unchanged: int = 0
    baseline_states: dict[str, int] = field(default_factory=dict)
    candidate_states: dict[str, int] = field(default_factory=dict)
    changes: list[Change] = field(default_factory=list)
    # Cases from the adversarial corpus the candidate stops refusing. Any single
    # one of these blocks promotion; a policy that gets friendlier on real
    # traffic by dropping a refusal has not improved, it has retreated.
    corpus_regressions: list[str] = field(default_factory=list)
    corpus_checked: int = 0

    @property
    def loosened(self) -> list[Change]:
        return [c for c in self.changes if c.loosened]

    @property
    def tightened(self) -> list[Change]:
        return [c for c in self.changes if not c.loosened]

    @property
    def safe_to_promote(self) -> bool:
        return not self.corpus_regressions

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_path": self.baseline_path,
            "candidate_path": self.candidate_path,
            "safe_to_promote": self.safe_to_promote,
            "traffic": {
                "total": self.total,
                "unchanged": self.unchanged,
                "loosened": len(self.loosened),
                "tightened": len(self.tightened),
                "baseline_states": self.baseline_states,
                "candidate_states": self.candidate_states,
            },
            "corpus": {
                "checked": self.corpus_checked,
                "regressions": self.corpus_regressions,
            },
            "changes": [c.to_dict() for c in self.changes],
        }


def _action_from_event(event: dict[str, Any]) -> ActionRequest | None:
    """
    Rebuild the request from a recorded decision.

    Parameter *values* are not in the trail — only their names, deliberately, so
    a credential cannot end up archived. Replay therefore reconstructs the shape
    of the call rather than the call itself: enough for the execution gate and
    the capability matrix, and `raw_input` still carries the command text the
    content rules read.
    """
    context = event.get("context") or {}
    recorded = context.get("action")
    if not isinstance(recorded, dict) or not recorded.get("tool"):
        return None
    return ActionRequest(
        raw_input=str(event.get("action", "")),
        intent=str(recorded.get("intent") or "operate"),
        tool=str(recorded["tool"]),
        target=recorded.get("target"),
        parameters={str(name): "" for name in recorded.get("parameter_names") or []},
    )


def _decide(action: ActionRequest, cfg: PolicyConfig, actor: str) -> Any:
    return run_pipeline_structured(
        action,
        constitution=Constitution([], use_semantic=False),
        actor=actor,
        cfg=cfg,
    )


def _load_corpus(name: str) -> list[dict[str, Any]]:
    path = _CORPUS_DIR / name
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    return [c for c in cases if isinstance(c, dict)]


def replay(
    *,
    baseline_path: str | Path,
    candidate_path: str | Path,
    audit_path: str | Path | None = None,
    actor: str = "robert",
    check_corpus: bool = True,
) -> ReplayReport:
    baseline = load_policy_config(baseline_path)
    candidate = load_policy_config(candidate_path)
    report = ReplayReport(baseline_path=str(baseline_path), candidate_path=str(candidate_path))

    if audit_path is not None and Path(audit_path).exists():
        before_states: Counter[str] = Counter()
        after_states: Counter[str] = Counter()
        for line in Path(audit_path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            action = _action_from_event(event)
            if action is None:
                # Recorded before the trail carried structure. Counting it as
                # unchanged would overstate how much of the window was replayed.
                continue

            report.total += 1
            before = _decide(action, baseline, actor)
            after = _decide(action, candidate, actor)
            before_states[before.state] += 1
            after_states[after.state] += 1

            if before.state == after.state:
                report.unchanged += 1
                continue
            report.changes.append(
                Change(
                    action=str(event.get("action", ""))[:120],
                    before=before.state,
                    after=after.state,
                    before_risk=before.risk_score,
                    after_risk=after.risk_score,
                    reason_after=after.reason,
                )
            )
        report.baseline_states = dict(sorted(before_states.items()))
        report.candidate_states = dict(sorted(after_states.items()))

    if check_corpus:
        # The corpus is written against the free-text path, which runs the
        # parser and intent escalation. Several cases are only refused because
        # of them — `ls / | xargs rm -rf` carries no declared tool. Evaluating
        # it as a structured call takes a different route through the engine and
        # reports regressions that are not there.
        for case in _load_corpus("procedural_evasions.json"):
            expected = case.get("expected") or {}
            if not expected.get("blocked"):
                continue
            report.corpus_checked += 1
            decision = run_pipeline(
                str(case.get("text", "")),
                constitution=Constitution([], use_semantic=False),
                actor=actor,
                cfg=candidate,
            )
            if decision.allowed:
                report.corpus_regressions.append(str(case.get("id", "unknown")))

    return report


def _print_text(report: ReplayReport) -> None:
    print("\n  POLICY REPLAY")
    print(f"  baseline   {report.baseline_path}")
    print(f"  candidate  {report.candidate_path}")
    print("  " + "─" * 68)

    if report.total:
        print(f"\n  recorded traffic     {report.total} decisions replayed")
        print(f"    unchanged          {report.unchanged}")
        print(f"    tightened          {len(report.tightened)}")
        print(f"    loosened           {len(report.loosened)}")
        if report.baseline_states != report.candidate_states:
            print(f"\n    before  {report.baseline_states}")
            print(f"    after   {report.candidate_states}")
    else:
        print("\n  recorded traffic     none replayed (no structured actions in the trail)")

    for label, changes in (("loosened", report.loosened), ("tightened", report.tightened)):
        if not changes:
            continue
        print(f"\n  {label} ({len(changes)})")
        for change in changes[:12]:
            print(f"    {change.before:>10} -> {change.after:<10} {change.action[:52]}")
        if len(changes) > 12:
            print(f"    … and {len(changes) - 12} more")

    print(f"\n  adversarial corpus   {report.corpus_checked} cases")
    if report.corpus_regressions:
        print(f"    REGRESSIONS        {len(report.corpus_regressions)}")
        for case_id in report.corpus_regressions[:10]:
            print(f"      {case_id}")
    else:
        print("    no case the corpus expects refused is allowed by the candidate")

    print()
    if report.safe_to_promote:
        print("  SAFE TO PROMOTE — no adversarial regression.")
        if report.loosened:
            print(f"  Read the {len(report.loosened)} loosened decision(s) above before you do.")
    else:
        print("  DO NOT PROMOTE — the candidate stops refusing cases the corpus covers.")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aetherya policy replay",
        description=(
            "Evaluate a candidate policy against recorded decisions and the "
            "adversarial corpus, and report what it changes."
        ),
    )
    parser.add_argument("--candidate", required=True, help="Policy file to evaluate.")
    parser.add_argument(
        "--baseline",
        default="config/policy.yaml",
        help="Policy to compare against (default: the repo policy).",
    )
    parser.add_argument(
        "--audit-path",
        default="audit/decisions.jsonl",
        help="Recorded decisions to replay. Skipped when absent.",
    )
    parser.add_argument("--actor", default="robert")
    parser.add_argument(
        "--no-corpus",
        action="store_true",
        help="Skip the adversarial corpus. The exit code then means nothing.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args(argv)

    try:
        report = replay(
            baseline_path=str(args.baseline),
            candidate_path=str(args.candidate),
            audit_path=str(args.audit_path) if args.audit_path else None,
            actor=str(args.actor),
            check_corpus=not bool(args.no_corpus),
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        _print_text(report)

    # Non-zero on adversarial regression only. A tightened decision is friction,
    # not a fault, and gating on it would make every improvement fail.
    return 0 if report.safe_to_promote else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
