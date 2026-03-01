#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = ROOT / "src"


def _run_cli(
    args: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    check: bool = True,
) -> tuple[subprocess.CompletedProcess[str], float]:
    cmd = [sys.executable, "-m", "aetherya.cli", *args]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_PATH)
    if extra_env:
        env.update(extra_env)

    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        check=False,
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if check and proc.returncode != 0:
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
        raise RuntimeError(
            "cli command failed: "
            f"args={args} returncode={proc.returncode} stdout={stdout!r} stderr={stderr!r}"
        )
    return proc, elapsed_ms


def _parse_json_output(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    streams = [proc.stdout.strip(), proc.stderr.strip()]
    for raw in streams:
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("unable to parse JSON payload from CLI output")


def _read_last_event(path: Path) -> dict[str, Any]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"audit file has no events: {path}")
    payload = json.loads(lines[-1])
    if not isinstance(payload, dict):
        raise ValueError("last audit event is not a JSON object")
    return payload


def _scenario_actor_spoof(tmpdir: Path, *, policy_path: Path) -> dict[str, Any]:
    constitution_path = tmpdir / "loose_rules.yaml"
    constitution_path.write_text(
        yaml.safe_dump(
            {
                "principles": [
                    {
                        "name": "LooseAssist",
                        "description": "intentionally permissive constitution for stress testing",
                        "priority": 1,
                        "keywords": ["help", "assist", "please"],
                        "risk": 1,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    raw_input = "mode:operative tool:filesystem target:/ param.operation=delete action: delete_all"
    proc, elapsed_ms = _run_cli(
        [
            "decide",
            raw_input,
            "--actor",
            "guest",
            "--policy-path",
            str(policy_path),
            "--constitution-path",
            str(constitution_path),
            "--json",
        ]
    )
    payload = _parse_json_output(proc)
    decision = payload.get("decision", {})
    if not isinstance(decision, dict):
        raise ValueError("actor spoof payload missing decision object")

    allowed = bool(decision.get("allowed"))
    mode = str(decision.get("mode", ""))
    violated_principle = decision.get("violated_principle")
    passed = (not allowed) and mode == "operative"

    return {
        "name": "actor_spoof",
        "passed": passed,
        "elapsed_ms": round(elapsed_ms, 3),
        "input": raw_input,
        "result": {
            "allowed": allowed,
            "mode": mode,
            "state": decision.get("state"),
            "risk_score": decision.get("risk_score"),
            "violated_principle": violated_principle,
            "reason": decision.get("reason"),
        },
        "expectation": {
            "allowed": False,
            "mode": "operative",
        },
    }


def _scenario_shadow_timeout(
    tmpdir: Path,
    *,
    policy_path: Path,
    actor: str,
    timeout_sec: float,
    max_wait_shadow_ms: float,
    max_no_wait_shadow_ms: float,
) -> dict[str, Any]:
    base_payload = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(base_payload, dict):
        raise ValueError("policy payload must be a mapping")

    shadow_payload = dict(base_payload)
    llm_shadow_payload = dict(shadow_payload.get("llm_shadow", {}))
    llm_shadow_payload.update(
        {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4o-mini",
            "temperature": 0.0,
            "max_tokens": 64,
            "timeout_sec": float(timeout_sec),
        }
    )
    shadow_payload["llm_shadow"] = llm_shadow_payload

    timeout_policy_path = tmpdir / "policy_shadow_timeout.yaml"
    timeout_policy_path.write_text(
        yaml.safe_dump(shadow_payload, sort_keys=False), encoding="utf-8"
    )

    wait_audit = tmpdir / "shadow_wait.jsonl"
    no_wait_audit = tmpdir / "shadow_nowait.jsonl"
    raw_input = (
        "mode:operative tool:filesystem target:/tmp/data.txt "
        "param.operation=write action: procedural wipe_disk request"
    )

    env_override = {"OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", "").strip() or "sk-test"}
    wait_proc, wait_ms = _run_cli(
        [
            "decide",
            raw_input,
            "--actor",
            actor,
            "--policy-path",
            str(timeout_policy_path),
            "--audit-path",
            str(wait_audit),
            "--wait-shadow",
            "--json",
        ],
        extra_env=env_override,
        check=True,
    )
    no_wait_proc, no_wait_ms = _run_cli(
        [
            "decide",
            raw_input,
            "--actor",
            actor,
            "--policy-path",
            str(timeout_policy_path),
            "--audit-path",
            str(no_wait_audit),
            "--no-wait-shadow",
            "--json",
        ],
        extra_env=env_override,
        check=True,
    )

    wait_payload = _parse_json_output(wait_proc)
    no_wait_payload = _parse_json_output(no_wait_proc)
    wait_decision = wait_payload.get("decision", {})
    no_wait_decision = no_wait_payload.get("decision", {})
    if not isinstance(wait_decision, dict) or not isinstance(no_wait_decision, dict):
        raise ValueError("shadow timeout payload missing decision object")

    wait_event = _read_last_event(wait_audit)
    no_wait_event = _read_last_event(no_wait_audit)
    wait_context = wait_event.get("context", {})
    no_wait_context = no_wait_event.get("context", {})
    wait_llm = wait_context.get("llm_shadow") if isinstance(wait_context, dict) else None
    no_wait_llm = no_wait_context.get("llm_shadow") if isinstance(no_wait_context, dict) else None

    same_core_decision = (
        wait_decision.get("allowed") == no_wait_decision.get("allowed")
        and wait_decision.get("state") == no_wait_decision.get("state")
        and wait_decision.get("risk_score") == no_wait_decision.get("risk_score")
    )
    wait_budget_ok = wait_ms <= float(max_wait_shadow_ms) if max_wait_shadow_ms > 0 else True
    no_wait_budget_ok = (
        no_wait_ms <= float(max_no_wait_shadow_ms) if max_no_wait_shadow_ms > 0 else True
    )
    wait_context_ok = isinstance(wait_llm, dict)
    no_wait_context_ok = no_wait_llm is None

    passed = (
        same_core_decision
        and wait_budget_ok
        and no_wait_budget_ok
        and wait_context_ok
        and no_wait_context_ok
    )

    return {
        "name": "shadow_timeout",
        "passed": passed,
        "input": raw_input,
        "expectation": {
            "same_core_decision": True,
            "wait_shadow_llm_context_present": True,
            "no_wait_shadow_llm_context_absent": True,
            "max_wait_shadow_ms": float(max_wait_shadow_ms),
            "max_no_wait_shadow_ms": float(max_no_wait_shadow_ms),
        },
        "result": {
            "wait_shadow": {
                "elapsed_ms": round(wait_ms, 3),
                "decision": {
                    "allowed": wait_decision.get("allowed"),
                    "state": wait_decision.get("state"),
                    "risk_score": wait_decision.get("risk_score"),
                },
                "llm_shadow": wait_llm,
            },
            "no_wait_shadow": {
                "elapsed_ms": round(no_wait_ms, 3),
                "decision": {
                    "allowed": no_wait_decision.get("allowed"),
                    "state": no_wait_decision.get("state"),
                    "risk_score": no_wait_decision.get("risk_score"),
                },
                "llm_shadow": no_wait_llm,
            },
            "checks": {
                "same_core_decision": same_core_decision,
                "wait_budget_ok": wait_budget_ok,
                "no_wait_budget_ok": no_wait_budget_ok,
                "wait_context_ok": wait_context_ok,
                "no_wait_context_ok": no_wait_context_ok,
            },
        },
    }


def _scenario_chain_integrity(
    tmpdir: Path,
    *,
    policy_path: Path,
    actor: str,
    iterations: int,
    max_verify_ms: float,
) -> dict[str, Any]:
    audit_path = tmpdir / "chain_integrity.jsonl"
    started = time.perf_counter()
    for idx in range(1, iterations + 1):
        _run_cli(
            [
                "decide",
                f"test input {idx}",
                "--actor",
                actor,
                "--policy-path",
                str(policy_path),
                "--audit-path",
                str(audit_path),
                "--json",
            ],
            check=True,
        )
    generation_ms = (time.perf_counter() - started) * 1000.0

    clean_proc, clean_verify_ms = _run_cli(
        [
            "audit",
            "verify",
            "--audit-path",
            str(audit_path),
            "--require-chain",
            "--json",
        ],
        check=False,
    )
    clean_report = _parse_json_output(clean_proc)

    tampered_path = tmpdir / "chain_integrity_tampered.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        raise ValueError("expected at least 2 audit events for tamper scenario")
    mid = len(lines) // 2
    lines[mid - 1], lines[mid] = lines[mid], lines[mid - 1]
    tampered_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tampered_proc, tampered_verify_ms = _run_cli(
        [
            "audit",
            "verify",
            "--audit-path",
            str(tampered_path),
            "--require-chain",
            "--json",
        ],
        check=False,
    )
    tampered_report = _parse_json_output(tampered_proc)

    clean_valid = int(clean_report.get("valid", 0))
    clean_invalid = int(clean_report.get("invalid", -1))
    tampered_invalid = int(tampered_report.get("invalid", 0))
    first_invalid = next(
        (item for item in tampered_report.get("results", []) if not bool(item.get("valid"))),
        None,
    )
    clean_budget_ok = clean_verify_ms <= float(max_verify_ms) if max_verify_ms > 0 else True
    tampered_budget_ok = tampered_verify_ms <= float(max_verify_ms) if max_verify_ms > 0 else True

    passed = (
        clean_proc.returncode == 0
        and clean_valid == iterations
        and clean_invalid == 0
        and tampered_proc.returncode != 0
        and tampered_invalid > 0
        and clean_budget_ok
        and tampered_budget_ok
    )

    return {
        "name": "chain_integrity",
        "passed": passed,
        "expectation": {
            "iterations": iterations,
            "clean_invalid": 0,
            "tampered_invalid_gt": 0,
            "max_verify_ms": float(max_verify_ms),
        },
        "result": {
            "generation_ms": round(generation_ms, 3),
            "clean_verify": {
                "elapsed_ms": round(clean_verify_ms, 3),
                "exit_code": clean_proc.returncode,
                "total": clean_report.get("total"),
                "valid": clean_report.get("valid"),
                "invalid": clean_report.get("invalid"),
            },
            "tampered_verify": {
                "elapsed_ms": round(tampered_verify_ms, 3),
                "exit_code": tampered_proc.returncode,
                "total": tampered_report.get("total"),
                "valid": tampered_report.get("valid"),
                "invalid": tampered_report.get("invalid"),
                "first_invalid": first_invalid,
            },
            "checks": {
                "clean_budget_ok": clean_budget_ok,
                "tampered_budget_ok": tampered_budget_ok,
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run pre-API CLI devil tests (spoofing, shadow timeout, chain integrity)."
    )
    parser.add_argument("--policy-path", default="config/policy.yaml")
    parser.add_argument("--actor", default="robert")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--shadow-timeout-sec", type=float, default=0.1)
    parser.add_argument(
        "--max-wait-shadow-ms",
        type=float,
        default=500.0,
        help="Fail if --wait-shadow execution exceeds this latency budget. Set <=0 to disable.",
    )
    parser.add_argument(
        "--max-no-wait-shadow-ms",
        type=float,
        default=150.0,
        help="Fail if --no-wait-shadow execution exceeds this latency budget. Set <=0 to disable.",
    )
    parser.add_argument(
        "--max-chain-verify-ms",
        type=float,
        default=200.0,
        help="Fail if chain verification exceeds this latency budget. Set <=0 to disable.",
    )
    parser.add_argument(
        "--output",
        default="audit/pre_api/pre_api_gate_report.json",
        help="Path to save JSON report.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep temporary scenario files for debugging.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON payload.")
    args = parser.parse_args(argv)

    policy_path = Path(args.policy_path)
    if not policy_path.exists():
        raise ValueError(f"policy file not found: {policy_path}")
    if args.iterations <= 1:
        raise ValueError("iterations must be > 1")

    tmp_ctx = tempfile.TemporaryDirectory(prefix="aetherya-pre-api-gate-")
    tmpdir = Path(tmp_ctx.name)

    started = time.perf_counter()
    scenarios: list[dict[str, Any]] = []
    try:
        scenarios.append(_scenario_actor_spoof(tmpdir, policy_path=policy_path))
        scenarios.append(
            _scenario_shadow_timeout(
                tmpdir,
                policy_path=policy_path,
                actor=str(args.actor),
                timeout_sec=float(args.shadow_timeout_sec),
                max_wait_shadow_ms=float(args.max_wait_shadow_ms),
                max_no_wait_shadow_ms=float(args.max_no_wait_shadow_ms),
            )
        )
        scenarios.append(
            _scenario_chain_integrity(
                tmpdir,
                policy_path=policy_path,
                actor=str(args.actor),
                iterations=int(args.iterations),
                max_verify_ms=float(args.max_chain_verify_ms),
            )
        )
    finally:
        if not args.keep_artifacts:
            tmp_ctx.cleanup()

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    passed = all(bool(item.get("passed")) for item in scenarios)

    payload = {
        "ok": passed,
        "policy_path": str(policy_path),
        "actor": str(args.actor),
        "iterations": int(args.iterations),
        "elapsed_ms": round(elapsed_ms, 3),
        "tmp_artifacts_kept": bool(args.keep_artifacts),
        "tmpdir": str(tmpdir),
        "scenarios": scenarios,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "pre_api_gate "
            f"ok={payload['ok']} "
            f"elapsed_ms={payload['elapsed_ms']:.3f} "
            f"report={output_path}"
        )
        for item in scenarios:
            print(
                "  - {name}: passed={passed}".format(
                    name=item.get("name", "unknown"),
                    passed=item.get("passed"),
                )
            )

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
