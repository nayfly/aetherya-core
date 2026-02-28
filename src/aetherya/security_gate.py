from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from random import Random
from typing import Any

from aetherya.audit import AuditLogger
from aetherya.audit_verify import main as audit_verify_main
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.explainability_report import render_html_from_audit
from aetherya.jailbreak import JailbreakGuard
from aetherya.pipeline import run_pipeline


@dataclass(frozen=True)
class SecurityGatePhase:
    name: str
    passed: bool
    details: dict[str, Any]


@dataclass(frozen=True)
class SecurityGateResult:
    passed: bool
    phases: list[SecurityGatePhase]
    manifest_path: str | None


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _resolve_attestation_key(explicit_key: str | None) -> str | None:
    raw = explicit_key if explicit_key is not None else os.getenv("AETHERYA_ATTESTATION_KEY", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned if cleaned else None


def _resolve_commit_sha(explicit_sha: str | None) -> str:
    raw = explicit_sha if explicit_sha is not None else os.getenv("GITHUB_SHA", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned if cleaned else "unknown"


def _load_cases(path: Path, *, expected_version: str = "v1") -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid corpus payload: {path}")
    if str(payload.get("version", "")).strip() != expected_version:
        raise ValueError(f"unsupported corpus version in {path}")

    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError(f"corpus cases must be list: {path}")

    cases: list[dict[str, Any]] = []
    for item in raw_cases:
        if isinstance(item, dict):
            cases.append(dict(item))
    if not cases:
        raise ValueError(f"corpus has no cases: {path}")
    return cases


def _load_snapshot_map(path: Path) -> dict[str, dict[str, Any]]:
    cases = _load_cases(path)
    snapshots: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case.get("id", "")).strip()
        expected = case.get("expected")
        if not case_id or not isinstance(expected, dict):
            continue
        snapshots[case_id] = dict(expected)
    if not snapshots:
        raise ValueError(f"snapshot map is empty: {path}")
    return snapshots


def _make_constitution() -> Constitution:
    principles = [
        Principle(
            "Non-harm",
            "Do not cause harm",
            priority=1,
            keywords=["harm", "kill", "attack"],
            risk=90,
        ),
    ]
    return Constitution(principles)


def _read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            events.append(payload)
    return events


def _write_events(path: Path, events: list[dict[str, Any]]) -> None:
    path.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8",
    )


def _mutate_attestation(events: list[dict[str, Any]], rng: Random) -> None:
    idx = rng.randrange(len(events))
    events[idx]["attestation"] = "hmac-sha256:tampered"


def _mutate_swap_decision_ids(events: list[dict[str, Any]], rng: Random) -> None:
    a = rng.randrange(len(events))
    b = rng.randrange(len(events))
    if a == b:
        b = (b + 1) % len(events)
    events[a]["decision_id"], events[b]["decision_id"] = (
        events[b]["decision_id"],
        events[a]["decision_id"],
    )


def _mutate_reorder_window(events: list[dict[str, Any]], rng: Random) -> None:
    if len(events) < 6:
        return
    start = rng.randrange(0, len(events) - 5)
    end = start + rng.randrange(3, 6)
    events[start:end] = list(reversed(events[start:end]))


def _mutate_chain(events: list[dict[str, Any]], rng: Random) -> None:
    idx = rng.randrange(len(events))
    events[idx]["prev_chain_hash"] = "sha256:deadbeef"


def _phase_corpus_regression(
    *,
    attacks_path: Path,
    snapshots_path: Path,
    policy_path: Path,
    attestation_key: str,
    workdir: Path,
    failure_report_dir: Path | None,
) -> SecurityGatePhase:
    attacks = _load_cases(attacks_path)
    snapshots = _load_snapshot_map(snapshots_path)
    cfg = load_policy_config(str(policy_path))
    constitution = _make_constitution()
    guard = JailbreakGuard()
    audit_path = workdir / "phase1_corpus_audit.jsonl"
    logger = AuditLogger(str(audit_path), attestation_key=attestation_key)

    failures: list[dict[str, Any]] = []
    total_guard_risk = 0
    total_decision_risk = 0

    for idx, case in enumerate(attacks):
        case_id = str(case.get("id", "")).strip() or f"case-{idx}"
        text = str(case.get("text", ""))
        snapshot = snapshots.get(case_id)
        if snapshot is None:
            failures.append({"case_id": case_id, "case_index": idx, "error": "snapshot_missing"})
            continue

        guard_result = guard.evaluate(text)
        guard_risk = int(guard_result.get("risk_score", 0)) if guard_result else 0
        total_guard_risk += guard_risk

        decision = run_pipeline(
            text, constitution=constitution, actor="robert", cfg=cfg, audit=logger
        )
        total_decision_risk += int(decision.risk_score)

        expected_risk = int(snapshot.get("risk_score", -1))
        expected_principle = str(snapshot.get("violated_principle", ""))
        expected_state = str(snapshot.get("state", ""))
        expected_allowed = bool(snapshot.get("allowed", False))

        case_errors: list[str] = []
        if int(decision.risk_score) != expected_risk:
            case_errors.append("risk_score mismatch")
        if str(decision.violated_principle) != expected_principle:
            case_errors.append("violated_principle mismatch")
        if str(decision.state) != expected_state:
            case_errors.append("state mismatch")
        if bool(decision.allowed) != expected_allowed:
            case_errors.append("allowed mismatch")

        if case_errors:
            failures.append(
                {
                    "case_id": case_id,
                    "case_index": idx,
                    "errors": case_errors,
                    "expected": snapshot,
                    "actual": {
                        "risk_score": decision.risk_score,
                        "violated_principle": decision.violated_principle,
                        "state": decision.state,
                        "allowed": decision.allowed,
                    },
                }
            )

    report_paths: list[str] = []
    if failure_report_dir and failures:
        failure_report_dir.mkdir(parents=True, exist_ok=True)
        for failure in failures:
            case_index = int(failure.get("case_index", -1))
            if case_index < 0:
                continue
            case_id = (
                str(failure.get("case_id", f"case_{case_index}")).strip() or f"case_{case_index}"
            )
            try:
                report_html = render_html_from_audit(
                    audit_path,
                    event_index=case_index,
                    title=f"AETHERYA Security Gate Failure - {case_id}",
                )
            except ValueError:
                continue
            report_path = failure_report_dir / f"{case_id}.html"
            report_path.write_text(report_html, encoding="utf-8")
            report_paths.append(str(report_path))

    total_cases = len(attacks)
    failed_cases = len(failures)
    passed_cases = total_cases - failed_cases
    avg_guard_risk = (total_guard_risk / total_cases) if total_cases else 0.0
    avg_decision_risk = (total_decision_risk / total_cases) if total_cases else 0.0
    details = {
        "attacks_path": str(attacks_path),
        "snapshots_path": str(snapshots_path),
        "audit_path": str(audit_path),
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "avg_guard_risk": round(avg_guard_risk, 4),
        "avg_decision_risk": round(avg_decision_risk, 4),
        "attenuation": round(avg_guard_risk - avg_decision_risk, 4),
        "failures": failures[:20],
        "failure_reports": report_paths,
    }
    return SecurityGatePhase(
        name="phase_1_corpus_regression", passed=failed_cases == 0, details=details
    )


def _phase_integrity_fuzz(
    *,
    attestation_key: str,
    workdir: Path,
    events: int,
    seed: int,
    mutation_rounds: int,
    expected_reject_code: int,
) -> SecurityGatePhase:
    audit_path = workdir / "phase2_tamper_audit.jsonl"
    logger = AuditLogger(str(audit_path), attestation_key=attestation_key)
    for idx in range(events):
        logger.log(
            actor="security-gate",
            action=f"phase2-event-{idx}",
            decision={"allowed": True, "risk_score": idx % 11, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"phase2-{idx}"},
        )

    mutated_events = _read_events(audit_path)
    if len(mutated_events) >= 8:
        mutated_events[1]["decision_id"], mutated_events[6]["decision_id"] = (
            mutated_events[6]["decision_id"],
            mutated_events[1]["decision_id"],
        )
        mutated_events[3:7] = list(reversed(mutated_events[3:7]))
    if len(mutated_events) >= 15:
        mutated_events[14]["attestation"] = "hmac-sha256:tampered"
    if len(mutated_events) >= 25:
        mutated_events[24]["prev_chain_hash"] = "sha256:deadbeef"

    rng = Random(seed)
    mutators = (
        _mutate_attestation,
        _mutate_swap_decision_ids,
        _mutate_reorder_window,
        _mutate_chain,
    )
    for _ in range(mutation_rounds):
        mutator = mutators[rng.randrange(len(mutators))]
        mutator(mutated_events, rng)

    _write_events(audit_path, mutated_events)

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = audit_verify_main(
            [
                "--audit-path",
                str(audit_path),
                "--attestation-key",
                attestation_key,
                "--require-hmac",
                "--require-chain",
                "--json",
            ]
        )

    stdout_text = out.getvalue().strip()
    stderr_text = err.getvalue().strip()
    report: dict[str, Any]
    if stdout_text:
        try:
            payload = json.loads(stdout_text)
            report = dict(payload) if isinstance(payload, dict) else {}
        except json.JSONDecodeError:
            report = {}
    else:
        report = {}

    invalid_count = int(report.get("invalid", 0)) if isinstance(report.get("invalid"), int) else 0
    total_count = int(report.get("total", 0)) if isinstance(report.get("total"), int) else 0
    passed = code == expected_reject_code and invalid_count > 0 and total_count == events
    details = {
        "audit_path": str(audit_path),
        "events": events,
        "seed": seed,
        "mutation_rounds": mutation_rounds,
        "expected_reject_code": expected_reject_code,
        "actual_code": code,
        "invalid": invalid_count,
        "total": total_count,
        "stderr": stderr_text,
    }
    return SecurityGatePhase(name="phase_2_integrity_fuzz", passed=passed, details=details)


def _phase_release_attestation(
    *,
    attestation_key: str,
    policy_path: Path,
    phases: list[SecurityGatePhase],
    manifest_output: Path,
    decision_count: int,
    commit_sha: str,
) -> SecurityGatePhase:
    payload = {
        "tool": "aetherya.security_gate",
        "version": "v1",
        "ts": datetime.now(UTC).isoformat(),
        "policy_path": str(policy_path),
        "decision_count": decision_count,
        "commit_sha": commit_sha,
        "phases": [
            {"name": phase.name, "passed": phase.passed, "details": phase.details}
            for phase in phases
        ],
    }
    signature = hmac.new(
        attestation_key.encode("utf-8"),
        _canonical_json(payload).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    manifest = {
        **payload,
        "signature_alg": "hmac-sha256",
        "signature": f"hmac-sha256:{signature}",
    }
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    manifest_output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    return SecurityGatePhase(
        name="phase_3_release_attestation",
        passed=True,
        details={
            "manifest_path": str(manifest_output),
            "signature_alg": "hmac-sha256",
            "decision_count": decision_count,
            "commit_sha": commit_sha,
        },
    )


def run_security_gate(
    *,
    attestation_key: str | None = None,
    commit_sha: str | None = None,
    policy_path: str | Path = "config/policy.yaml",
    attacks_path: str | Path = "tests/fixtures/security_corpus/v1/jailbreak_attacks.json",
    snapshots_path: str | Path = "tests/fixtures/security_corpus/v1/attack_decision_snapshots.json",
    workdir: str | Path = "audit/security_gate",
    failure_report_dir: str | Path | None = None,
    manifest_output: str | Path = "audit/security_gate/security_manifest.json",
    phase2_events: int = 1000,
    phase2_seed: int = 1337,
    phase2_mutation_rounds: int = 32,
    phase2_expected_reject_code: int = 1,
) -> SecurityGateResult:
    resolved_key = _resolve_attestation_key(attestation_key)
    if not resolved_key:
        raise ValueError("attestation key is required (arg or AETHERYA_ATTESTATION_KEY)")
    resolved_commit_sha = _resolve_commit_sha(commit_sha)

    resolved_policy_path = Path(policy_path)
    resolved_attacks_path = Path(attacks_path)
    resolved_snapshots_path = Path(snapshots_path)
    resolved_workdir = Path(workdir)
    resolved_workdir.mkdir(parents=True, exist_ok=True)
    resolved_manifest_output = Path(manifest_output)
    resolved_failure_report_dir = Path(failure_report_dir) if failure_report_dir else None

    phase_1 = _phase_corpus_regression(
        attacks_path=resolved_attacks_path,
        snapshots_path=resolved_snapshots_path,
        policy_path=resolved_policy_path,
        attestation_key=resolved_key,
        workdir=resolved_workdir,
        failure_report_dir=resolved_failure_report_dir,
    )
    phase_2 = _phase_integrity_fuzz(
        attestation_key=resolved_key,
        workdir=resolved_workdir,
        events=phase2_events,
        seed=phase2_seed,
        mutation_rounds=phase2_mutation_rounds,
        expected_reject_code=phase2_expected_reject_code,
    )

    phases: list[SecurityGatePhase] = [phase_1, phase_2]
    manifest_path: str | None = None
    if phase_1.passed and phase_2.passed:
        decision_count = int(phase_1.details.get("total_cases", 0))
        phase_3 = _phase_release_attestation(
            attestation_key=resolved_key,
            policy_path=resolved_policy_path,
            phases=phases,
            manifest_output=resolved_manifest_output,
            decision_count=decision_count,
            commit_sha=resolved_commit_sha,
        )
        phases.append(phase_3)
        manifest_path = str(resolved_manifest_output)
    else:
        phases.append(
            SecurityGatePhase(
                name="phase_3_release_attestation",
                passed=False,
                details={"skipped": True, "reason": "previous phase failed"},
            )
        )

    return SecurityGateResult(
        passed=all(phase.passed for phase in phases),
        phases=phases,
        manifest_path=manifest_path,
    )


def _format_text_result(result: SecurityGateResult) -> str:
    lines = [f"security_gate passed={result.passed}"]
    for phase in result.phases:
        lines.append(f"- {phase.name}: {'PASS' if phase.passed else 'FAIL'}")
    if result.manifest_path:
        lines.append(f"manifest: {result.manifest_path}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AETHERYA Security Gate (3-phase validation).")
    parser.add_argument(
        "--attestation-key", default=None, help="HMAC key (or use env AETHERYA_ATTESTATION_KEY)."
    )
    parser.add_argument(
        "--commit-sha",
        default=None,
        help="Commit SHA included in manifest (or use env GITHUB_SHA).",
    )
    parser.add_argument("--policy-path", default="config/policy.yaml", help="Policy config path.")
    parser.add_argument(
        "--attacks-path",
        default="tests/fixtures/security_corpus/v1/jailbreak_attacks.json",
        help="Attack corpus path.",
    )
    parser.add_argument(
        "--snapshots-path",
        default="tests/fixtures/security_corpus/v1/attack_decision_snapshots.json",
        help="Expected decision snapshot path.",
    )
    parser.add_argument(
        "--workdir",
        default="audit/security_gate",
        help="Working directory for generated artifacts.",
    )
    parser.add_argument(
        "--failure-report-dir",
        default="",
        help="Optional directory for HTML reports of corpus failures.",
    )
    parser.add_argument(
        "--manifest-output",
        default="audit/security_gate/security_manifest.json",
        help="Output path for release attestation manifest.",
    )
    parser.add_argument(
        "--phase2-events", type=int, default=1000, help="Number of events for integrity fuzz phase."
    )
    parser.add_argument(
        "--phase2-seed", type=int, default=1337, help="Deterministic seed for mutator."
    )
    parser.add_argument(
        "--phase2-mutation-rounds",
        type=int,
        default=32,
        help="Mutation rounds for tamper campaign.",
    )
    parser.add_argument(
        "--phase2-expected-reject-code",
        type=int,
        default=1,
        help="Expected audit_verify exit code for tampered log rejection.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        result = run_security_gate(
            attestation_key=args.attestation_key,
            commit_sha=args.commit_sha,
            policy_path=args.policy_path,
            attacks_path=args.attacks_path,
            snapshots_path=args.snapshots_path,
            workdir=args.workdir,
            failure_report_dir=args.failure_report_dir or None,
            manifest_output=args.manifest_output,
            phase2_events=args.phase2_events,
            phase2_seed=args.phase2_seed,
            phase2_mutation_rounds=args.phase2_mutation_rounds,
            phase2_expected_reject_code=args.phase2_expected_reject_code,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, sort_keys=True))
    else:
        print(_format_text_result(result))
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
