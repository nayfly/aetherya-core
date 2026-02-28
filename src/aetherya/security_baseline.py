from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from random import Random
from typing import Any

from aetherya.audit import AuditLogger
from aetherya.audit_verify import verify_audit_file
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.jailbreak import JailbreakGuard
from aetherya.pipeline import run_pipeline


@dataclass(frozen=True)
class SecurityBaselineResult:
    passed: bool
    baseline_path: str
    actual: dict[str, Any]
    expected: dict[str, Any]
    differences: list[dict[str, Any]]


def _resolve_attestation_key(explicit_key: str | None) -> str:
    raw = explicit_key if explicit_key is not None else os.getenv("AETHERYA_ATTESTATION_KEY", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned if cleaned else "baseline-key"


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


def _load_baseline(path: Path, *, expected_version: str = "v1") -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid baseline payload: {path}")
    if str(payload.get("version", "")).strip() != expected_version:
        raise ValueError(f"unsupported baseline version in {path}")
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"baseline metrics must be dict: {path}")
    return dict(metrics)


def _write_baseline(path: Path, metrics: dict[str, Any], *, version: str = "v1") -> None:
    payload = {
        "version": version,
        "kind": "security_stress_baseline",
        "metrics": metrics,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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


def _reset_file(path: Path) -> None:
    if path.exists():
        path.unlink()


def _round4(value: float) -> float:
    return round(value, 4)


def _count_invalid(records: list[Any]) -> int:
    return sum(1 for record in records if not bool(record.verification.valid))


def _count_error(records: list[Any], target: str) -> int:
    return sum(1 for record in records if target in list(record.verification.errors))


def _compute_jailbreak_metrics(
    *,
    attacks_path: Path,
    benign_path: Path,
    policy_path: Path,
) -> dict[str, Any]:
    attack_cases = _load_cases(attacks_path)
    benign_cases = _load_cases(benign_path)

    guard = JailbreakGuard()
    cfg = load_policy_config(str(policy_path))
    constitution = _make_constitution()

    attack_guard_hits = 0
    attack_blocked = 0
    attack_total_guard_risk = 0
    attack_total_decision_risk = 0
    for case in attack_cases:
        text = str(case.get("text", ""))
        guard_result = guard.evaluate(text)
        if guard_result is not None:
            attack_guard_hits += 1
            attack_total_guard_risk += int(guard_result.get("risk_score", 0))

        decision = run_pipeline(text, constitution=constitution, actor="robert", cfg=cfg)
        if not decision.allowed:
            attack_blocked += 1
        attack_total_decision_risk += int(decision.risk_score)

    benign_guard_hits = 0
    benign_allowed = 0
    benign_prompt_safety_violations = 0
    for case in benign_cases:
        text = str(case.get("text", ""))
        guard_result = guard.evaluate(text)
        if guard_result is not None:
            benign_guard_hits += 1

        decision = run_pipeline(text, constitution=constitution, actor="robert", cfg=cfg)
        if decision.allowed:
            benign_allowed += 1
        if str(decision.violated_principle) == "PromptSafety":
            benign_prompt_safety_violations += 1

    attack_total = len(attack_cases)
    benign_total = len(benign_cases)
    return {
        "attacks_total": attack_total,
        "attacks_guard_hits": attack_guard_hits,
        "attacks_blocked": attack_blocked,
        "attacks_block_rate": _round4(attack_blocked / attack_total),
        "attacks_avg_guard_risk": _round4(attack_total_guard_risk / attack_total),
        "attacks_avg_decision_risk": _round4(attack_total_decision_risk / attack_total),
        "benign_total": benign_total,
        "benign_guard_hits": benign_guard_hits,
        "benign_allowed": benign_allowed,
        "benign_allow_rate": _round4(benign_allowed / benign_total),
        "benign_prompt_safety_violations": benign_prompt_safety_violations,
    }


def _compute_integrity_metrics(
    *,
    workdir: Path,
    attestation_key: str,
    events: int,
    tamper_stride: int,
    fuzz_events: int,
    fuzz_seed: int,
    fuzz_rounds: int,
) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)

    clean_path = workdir / "baseline_integrity_clean.jsonl"
    _reset_file(clean_path)
    clean_logger = AuditLogger(str(clean_path), attestation_key=attestation_key)
    for idx in range(events):
        clean_logger.log(
            actor="baseline-bot",
            action=f"event-{idx}",
            decision={"allowed": True, "risk_score": idx % 7, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"baseline-{idx}"},
        )
    clean_records = verify_audit_file(
        clean_path,
        require_hmac=True,
        require_chain=True,
        attestation_key=attestation_key,
    )

    tampered_path = workdir / "baseline_integrity_tampered.jsonl"
    tampered_events = _read_events(clean_path)
    tampered_indices = list(range(0, len(tampered_events), tamper_stride))
    for idx in tampered_indices:
        tampered_events[idx]["attestation"] = "hmac-sha256:tampered"
    _write_events(tampered_path, tampered_events)
    tampered_records = verify_audit_file(
        tampered_path,
        require_hmac=True,
        attestation_key=attestation_key,
    )

    chain_path = workdir / "baseline_integrity_chain_break.jsonl"
    chain_events = _read_events(clean_path)
    chain_window_start = min(40, max(0, len(chain_events) - 5))
    chain_window_end = min(len(chain_events), chain_window_start + 5)
    chain_events[chain_window_start:chain_window_end] = list(
        reversed(chain_events[chain_window_start:chain_window_end])
    )
    _write_events(chain_path, chain_events)
    chain_records = verify_audit_file(
        chain_path,
        require_hmac=True,
        require_chain=True,
        attestation_key=attestation_key,
    )

    fuzz_path = workdir / "baseline_tamper_fuzz.jsonl"
    _reset_file(fuzz_path)
    fuzz_logger = AuditLogger(str(fuzz_path), attestation_key=attestation_key)
    for idx in range(fuzz_events):
        fuzz_logger.log(
            actor="baseline-bot",
            action=f"fuzz-{idx}",
            decision={"allowed": True, "risk_score": idx % 11, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"fuzz-{idx}"},
        )

    fuzz_events_payload = _read_events(fuzz_path)
    if len(fuzz_events_payload) >= 120:
        fuzz_events_payload[7]["decision_id"], fuzz_events_payload[119]["decision_id"] = (
            fuzz_events_payload[119]["decision_id"],
            fuzz_events_payload[7]["decision_id"],
        )
    if len(fuzz_events_payload) >= 45:
        fuzz_events_payload[40:45] = list(reversed(fuzz_events_payload[40:45]))
    if len(fuzz_events_payload) >= 91:
        fuzz_events_payload[90]["attestation"] = "hmac-sha256:tampered"

    rng = Random(fuzz_seed)
    for _ in range(fuzz_rounds):
        if not fuzz_events_payload:
            break
        mutation_type = rng.randrange(4)
        if mutation_type == 0:
            idx = rng.randrange(len(fuzz_events_payload))
            fuzz_events_payload[idx]["attestation"] = "hmac-sha256:tampered"
        elif mutation_type == 1:
            a = rng.randrange(len(fuzz_events_payload))
            b = rng.randrange(len(fuzz_events_payload))
            if a == b:
                b = (b + 1) % len(fuzz_events_payload)
            fuzz_events_payload[a]["decision_id"], fuzz_events_payload[b]["decision_id"] = (
                fuzz_events_payload[b]["decision_id"],
                fuzz_events_payload[a]["decision_id"],
            )
        elif mutation_type == 2:
            if len(fuzz_events_payload) >= 6:
                start = rng.randrange(0, len(fuzz_events_payload) - 5)
                end = min(len(fuzz_events_payload), start + rng.randrange(3, 6))
                fuzz_events_payload[start:end] = list(reversed(fuzz_events_payload[start:end]))
        else:
            idx = rng.randrange(len(fuzz_events_payload))
            fuzz_events_payload[idx]["prev_chain_hash"] = "sha256:deadbeef"

    _write_events(fuzz_path, fuzz_events_payload)
    fuzz_records = verify_audit_file(
        fuzz_path,
        require_hmac=True,
        require_chain=True,
        attestation_key=attestation_key,
    )

    return {
        "integrity_events": events,
        "clean_invalid": _count_invalid(clean_records),
        "tamper_stride": tamper_stride,
        "tampered_events": len(tampered_indices),
        "tampered_invalid": _count_invalid(tampered_records),
        "tampered_attestation_mismatch": _count_error(tampered_records, "attestation mismatch"),
        "chain_window_start": chain_window_start,
        "chain_window_size": chain_window_end - chain_window_start,
        "chain_invalid": _count_invalid(chain_records),
        "chain_prev_hash_mismatch": _count_error(chain_records, "prev_chain_hash mismatch"),
        "chain_hash_mismatch": _count_error(chain_records, "chain_hash mismatch"),
        "fuzz_events": fuzz_events,
        "fuzz_seed": fuzz_seed,
        "fuzz_rounds": fuzz_rounds,
        "fuzz_invalid": _count_invalid(fuzz_records),
        "fuzz_decision_id_mismatch": _count_error(fuzz_records, "decision_id mismatch"),
        "fuzz_attestation_mismatch": _count_error(fuzz_records, "attestation mismatch"),
        "fuzz_prev_chain_hash_mismatch": _count_error(fuzz_records, "prev_chain_hash mismatch"),
        "fuzz_chain_hash_mismatch": _count_error(fuzz_records, "chain_hash mismatch"),
    }


def _diff_values(
    *,
    expected: Any,
    actual: Any,
    path: str,
    differences: list[dict[str, Any]],
) -> None:
    if isinstance(expected, dict) and isinstance(actual, dict):
        keys = sorted(set(expected.keys()) | set(actual.keys()))
        for key in keys:
            child_path = f"{path}.{key}" if path else key
            if key not in expected:
                differences.append(
                    {"path": child_path, "expected": "<missing>", "actual": actual[key]}
                )
                continue
            if key not in actual:
                differences.append(
                    {"path": child_path, "expected": expected[key], "actual": "<missing>"}
                )
                continue
            _diff_values(
                expected=expected[key],
                actual=actual[key],
                path=child_path,
                differences=differences,
            )
        return

    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            differences.append(
                {"path": path, "expected": f"len={len(expected)}", "actual": f"len={len(actual)}"}
            )
            return
        for idx, (expected_item, actual_item) in enumerate(zip(expected, actual, strict=True)):
            child_path = f"{path}[{idx}]"
            _diff_values(
                expected=expected_item,
                actual=actual_item,
                path=child_path,
                differences=differences,
            )
        return

    if expected != actual:
        differences.append({"path": path or "<root>", "expected": expected, "actual": actual})


def compute_security_baseline_metrics(
    *,
    policy_path: Path,
    attacks_path: Path,
    benign_path: Path,
    workdir: Path,
    attestation_key: str,
    integrity_events: int,
    integrity_tamper_stride: int,
    fuzz_events: int,
    fuzz_seed: int,
    fuzz_rounds: int,
) -> dict[str, Any]:
    if integrity_events <= 0:
        raise ValueError("integrity_events must be > 0")
    if integrity_tamper_stride <= 0:
        raise ValueError("integrity_tamper_stride must be > 0")
    if fuzz_events <= 0:
        raise ValueError("fuzz_events must be > 0")
    if fuzz_rounds < 0:
        raise ValueError("fuzz_rounds must be >= 0")

    jailbreak_metrics = _compute_jailbreak_metrics(
        attacks_path=attacks_path,
        benign_path=benign_path,
        policy_path=policy_path,
    )
    integrity_metrics = _compute_integrity_metrics(
        workdir=workdir,
        attestation_key=attestation_key,
        events=integrity_events,
        tamper_stride=integrity_tamper_stride,
        fuzz_events=fuzz_events,
        fuzz_seed=fuzz_seed,
        fuzz_rounds=fuzz_rounds,
    )
    return {
        "jailbreak": jailbreak_metrics,
        "integrity": integrity_metrics,
    }


def run_security_baseline(
    *,
    baseline_path: str | Path = "tests/fixtures/security_baseline/v1/stress_baseline.json",
    policy_path: str | Path = "config/policy.yaml",
    attacks_path: str | Path = "tests/fixtures/security_corpus/v1/jailbreak_attacks.json",
    benign_path: str | Path = "tests/fixtures/security_corpus/v1/benign_security_prompts.json",
    workdir: str | Path = "audit/security_baseline",
    attestation_key: str | None = None,
    integrity_events: int = 300,
    integrity_tamper_stride: int = 15,
    fuzz_events: int = 160,
    fuzz_seed: int = 1337,
    fuzz_rounds: int = 18,
    update_baseline: bool = False,
) -> SecurityBaselineResult:
    resolved_baseline_path = Path(baseline_path)
    resolved_policy_path = Path(policy_path)
    resolved_attacks_path = Path(attacks_path)
    resolved_benign_path = Path(benign_path)
    resolved_workdir = Path(workdir)
    resolved_key = _resolve_attestation_key(attestation_key)

    actual = compute_security_baseline_metrics(
        policy_path=resolved_policy_path,
        attacks_path=resolved_attacks_path,
        benign_path=resolved_benign_path,
        workdir=resolved_workdir,
        attestation_key=resolved_key,
        integrity_events=integrity_events,
        integrity_tamper_stride=integrity_tamper_stride,
        fuzz_events=fuzz_events,
        fuzz_seed=fuzz_seed,
        fuzz_rounds=fuzz_rounds,
    )

    if update_baseline or not resolved_baseline_path.exists():
        _write_baseline(resolved_baseline_path, actual, version="v1")

    expected = _load_baseline(resolved_baseline_path)
    differences: list[dict[str, Any]] = []
    _diff_values(expected=expected, actual=actual, path="", differences=differences)

    return SecurityBaselineResult(
        passed=not differences,
        baseline_path=str(resolved_baseline_path),
        actual=actual,
        expected=expected,
        differences=differences,
    )


def _format_text_result(result: SecurityBaselineResult, *, max_diff: int = 10) -> str:
    lines = [f"security_baseline passed={result.passed}", f"baseline: {result.baseline_path}"]
    if not result.differences:
        lines.append("differences: 0")
        return "\n".join(lines)

    lines.append(f"differences: {len(result.differences)}")
    for diff in result.differences[:max_diff]:
        lines.append(f"- {diff['path']}: expected={diff['expected']!r} actual={diff['actual']!r}")
    if len(result.differences) > max_diff:
        lines.append(f"... {len(result.differences) - max_diff} more differences")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate deterministic security stress baseline against versioned snapshot."
    )
    parser.add_argument(
        "--baseline-path",
        default="tests/fixtures/security_baseline/v1/stress_baseline.json",
        help="Versioned baseline snapshot path.",
    )
    parser.add_argument("--policy-path", default="config/policy.yaml", help="Policy config path.")
    parser.add_argument(
        "--attacks-path",
        default="tests/fixtures/security_corpus/v1/jailbreak_attacks.json",
        help="Attack corpus path.",
    )
    parser.add_argument(
        "--benign-path",
        default="tests/fixtures/security_corpus/v1/benign_security_prompts.json",
        help="Benign corpus path.",
    )
    parser.add_argument(
        "--workdir",
        default="audit/security_baseline",
        help="Working directory for generated temporary logs.",
    )
    parser.add_argument(
        "--attestation-key",
        default=None,
        help="Optional attestation key (falls back to env or deterministic baseline key).",
    )
    parser.add_argument("--integrity-events", type=int, default=300, help="Integrity event count.")
    parser.add_argument(
        "--integrity-tamper-stride",
        type=int,
        default=15,
        help="Stride for deterministic tampering in integrity phase.",
    )
    parser.add_argument("--fuzz-events", type=int, default=160, help="Fuzz campaign event count.")
    parser.add_argument("--fuzz-seed", type=int, default=1337, help="Deterministic fuzz seed.")
    parser.add_argument("--fuzz-rounds", type=int, default=18, help="Fuzz mutation rounds.")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Rewrite baseline snapshot with current metrics.",
    )
    parser.add_argument("--max-diff", type=int, default=10, help="Max differences in text output.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        result = run_security_baseline(
            baseline_path=args.baseline_path,
            policy_path=args.policy_path,
            attacks_path=args.attacks_path,
            benign_path=args.benign_path,
            workdir=args.workdir,
            attestation_key=args.attestation_key,
            integrity_events=args.integrity_events,
            integrity_tamper_stride=args.integrity_tamper_stride,
            fuzz_events=args.fuzz_events,
            fuzz_seed=args.fuzz_seed,
            fuzz_rounds=args.fuzz_rounds,
            update_baseline=args.update_baseline,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, sort_keys=True))
    else:
        print(_format_text_result(result, max_diff=max(1, args.max_diff)))
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
