from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from aetherya.actions import validate_action_request, validate_actor
from aetherya.approval_proof import (
    approval_scope_hash,
    build_approval_proof,
    load_approval_keyring,
)
from aetherya.audit import AuditLogger
from aetherya.audit_verify import main as audit_verify_main
from aetherya.chaos_benchmark import main as chaos_benchmark_main
from aetherya.config import LLMShadowConfig, PolicyConfig, load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.explainability_render import main as explainability_render_main
from aetherya.explainability_report import main as explainability_report_main
from aetherya.parser import parse_user_input
from aetherya.pipeline import run_pipeline
from aetherya.pipeline_benchmark import main as pipeline_benchmark_main
from aetherya.security_baseline import main as security_baseline_main
from aetherya.security_gate import main as security_gate_main
from aetherya.verify_release_artifacts import main as verify_release_artifacts_main


def _default_constitution() -> Constitution:
    return Constitution(
        [
            Principle(
                "PromptSafety",
                "Reject prompt injection patterns",
                priority=1,
                keywords=["ignore previous instructions", "system prompt", "developer message"],
                risk=95,
            ),
            Principle(
                "Non-harm",
                "Do not support harmful intent",
                priority=2,
                keywords=["kill", "attack", "harm"],
                risk=90,
            ),
            Principle(
                "DataProtection",
                "Protect sensitive data from exfiltration",
                priority=3,
                keywords=["exfiltrate", "dump db", "secrets", "api key"],
                risk=88,
            ),
            Principle(
                "SystemIntegrity",
                "Protect critical system operations",
                priority=4,
                keywords=["rm -rf /", "mkfs", "drop table"],
                risk=92,
            ),
        ]
    )


def _load_constitution(path: Path) -> Constitution:
    if not path.exists():
        raise ValueError(f"constitution file not found: {path}")

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw_principles: Any
    if isinstance(payload, dict):
        raw_principles = payload.get("principles")
    else:
        raw_principles = payload

    if not isinstance(raw_principles, list):
        raise ValueError("constitution payload must contain a 'principles' list or be a list")
    if not raw_principles:
        raise ValueError("constitution principles list must be non-empty")

    principles: list[Principle] = []
    for idx, raw_item in enumerate(raw_principles):
        if not isinstance(raw_item, dict):
            raise ValueError(f"constitution principle at index {idx} must be a mapping")

        name = str(raw_item.get("name", "")).strip()
        description = str(raw_item.get("description", "")).strip()
        if not name:
            raise ValueError(f"constitution principle at index {idx} has empty name")
        if not description:
            raise ValueError(f"constitution principle at index {idx} has empty description")

        raw_keywords = raw_item.get("keywords", [])
        if not isinstance(raw_keywords, list):
            raise ValueError(f"constitution principle '{name}' keywords must be a list")

        principles.append(
            Principle(
                name=name,
                description=description,
                priority=int(raw_item.get("priority", 100)),
                keywords=[str(keyword) for keyword in raw_keywords if str(keyword).strip()],
                risk=int(raw_item.get("risk", 50)),
            )
        )
    return Constitution(principles)


def _resolve_raw_input(raw_input: str | None, inline_input: str | None) -> str:
    if raw_input and inline_input:
        raise ValueError("provide either positional raw_input or --input, not both")
    if inline_input is not None:
        cleaned = inline_input.strip()
        if not cleaned:
            raise ValueError("--input must be non-empty")
        return cleaned
    if raw_input is not None:
        cleaned = raw_input.strip()
        if not cleaned:
            raise ValueError("raw_input must be non-empty")
        return cleaned

    if sys.stdin.isatty():
        raise ValueError("missing raw_input (use positional arg, --input, or pipe stdin)")
    stdin_text = sys.stdin.read().strip()
    if not stdin_text:
        raise ValueError("stdin input is empty")
    return stdin_text


def _maybe_read_last_event(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return None
    payload = json.loads(lines[-1])
    if isinstance(payload, dict):
        return payload
    return None


def _llm_shadow_disabled(cfg: PolicyConfig, *, wait_shadow: bool) -> PolicyConfig:
    if wait_shadow:
        return cfg
    shadow_cfg: LLMShadowConfig = cfg.llm_shadow
    if not shadow_cfg.enabled:
        return cfg
    return replace(cfg, llm_shadow=replace(shadow_cfg, enabled=False))


def _cmd_decide(args: argparse.Namespace) -> int:
    raw_input = _resolve_raw_input(args.raw_input, args.inline_input)
    candidate_response = (
        str(args.candidate_response).strip() if args.candidate_response is not None else None
    )
    if candidate_response == "":
        candidate_response = None
    policy_path = Path(args.policy_path)
    cfg = load_policy_config(policy_path)
    cfg_effective = _llm_shadow_disabled(cfg, wait_shadow=bool(args.wait_shadow))

    constitution_path = Path(args.constitution_path) if args.constitution_path else None
    constitution = (
        _load_constitution(constitution_path) if constitution_path else _default_constitution()
    )

    audit_path = Path(args.audit_path) if args.audit_path else None
    audit = AuditLogger(str(audit_path)) if audit_path else None

    decision = run_pipeline(
        raw_input,
        constitution=constitution,
        actor=str(args.actor),
        cfg=cfg_effective,
        audit=audit,
        response_text=candidate_response,
    )

    event = _maybe_read_last_event(audit_path)
    payload = {
        "decision": decision.to_dict(),
        "meta": {
            "actor": str(args.actor),
            "policy_path": str(policy_path),
            "constitution_path": str(constitution_path) if constitution_path else None,
            "wait_shadow": bool(args.wait_shadow),
            "candidate_response_present": candidate_response is not None,
            "llm_shadow_enabled_config": bool(cfg.llm_shadow.enabled),
            "llm_shadow_enabled_effective": bool(cfg_effective.llm_shadow.enabled),
            "audit_path": str(audit_path) if audit_path else None,
            "policy_fingerprint": cfg.policy_fingerprint,
            "event_id": event.get("event_id") if isinstance(event, dict) else None,
            "decision_id": event.get("decision_id") if isinstance(event, dict) else None,
        },
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        decision_payload = payload["decision"]
        meta_payload = payload["meta"]
        print(
            "allowed={allowed} state={state} risk_score={risk} reason={reason}".format(
                allowed=decision_payload["allowed"],
                state=decision_payload["state"],
                risk=decision_payload["risk_score"],
                reason=decision_payload["reason"],
            )
        )
        print(
            "actor={actor} wait_shadow={wait_shadow} llm_shadow_effective={llm_enabled}".format(
                actor=meta_payload["actor"],
                wait_shadow=meta_payload["wait_shadow"],
                llm_enabled=meta_payload["llm_shadow_enabled_effective"],
            )
        )
        if meta_payload["event_id"]:
            print(
                "event_id={event_id} decision_id={decision_id}".format(
                    event_id=meta_payload["event_id"],
                    decision_id=meta_payload["decision_id"],
                )
            )
    return 0


def _cmd_confirmation_sign(args: argparse.Namespace) -> int:
    raw_input = _resolve_raw_input(args.raw_input, args.inline_input)
    actor = validate_actor(str(args.actor))
    policy_path = Path(args.policy_path)
    cfg = load_policy_config(policy_path)
    signed_cfg = cfg.confirmation.evidence.signed_proof

    if not signed_cfg.enabled:
        raise ValueError("confirmation.evidence.signed_proof.enabled=false in current policy")

    key_env = str(args.key_env).strip() if args.key_env is not None else signed_cfg.key_env
    if not key_env:
        raise ValueError("key_env must be non-empty")
    keyring_env = signed_cfg.keyring_env
    active_kid = signed_cfg.active_kid
    keyring = load_approval_keyring(
        keyring_env=keyring_env,
        fallback_env=key_env,
        fallback_kid=active_kid,
    )
    secret = keyring.get(active_kid, "").strip()
    if not secret:
        raise ValueError(
            f"missing approval key for kid '{active_kid}' in env vars: {keyring_env} or {key_env}"
        )

    expires_in_sec = (
        int(args.expires_in_sec)
        if args.expires_in_sec is not None
        else signed_cfg.max_valid_for_sec
    )
    if expires_in_sec <= 0:
        raise ValueError("expires_in_sec must be > 0")
    if expires_in_sec > signed_cfg.max_valid_for_sec:
        raise ValueError(
            f"expires_in_sec exceeds policy max_valid_for_sec ({signed_cfg.max_valid_for_sec})"
        )

    action = validate_action_request(parse_user_input(raw_input))
    if action.intent != "operate":
        raise ValueError("confirmation sign requires an operative action input")

    exclude_keys = {name for name in action.parameters if str(name).startswith("confirm_")}
    proof, expires_at = build_approval_proof(
        secret=secret,
        kid=active_kid,
        actor=actor,
        action=action,
        ttl_sec=expires_in_sec,
        now_ts=args.now_ts,
        exclude_params=exclude_keys,
    )
    scope_hash = approval_scope_hash(actor=actor, action=action, exclude_params=exclude_keys)

    payload = {
        "ok": True,
        "approval_proof": proof,
        "expires_at": int(expires_at),
        "expires_in_sec": int(expires_in_sec),
        "scope_hash": scope_hash,
        "actor": actor,
        "tool": action.tool,
        "target": action.target,
        "operation": action.parameters.get("operation"),
        "policy_path": str(policy_path),
        "key_env": key_env,
        "keyring_env": keyring_env,
        "kid": active_kid,
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "approval_proof={proof} expires_at={expires_at} scope_hash={scope_hash}".format(
                proof=payload["approval_proof"],
                expires_at=payload["expires_at"],
                scope_hash=payload["scope_hash"],
            )
        )
        print(
            "actor={actor} tool={tool} operation={operation} key_env={key_env}".format(
                actor=payload["actor"],
                tool=payload["tool"],
                operation=payload["operation"],
                key_env=payload["key_env"],
            )
        )
    return 0


def _cmd_forward(args: argparse.Namespace) -> int:
    target_main = getattr(args, "target_main", None)
    forward_args = list(getattr(args, "forward_args", []))
    if forward_args and forward_args[0] == "--":
        forward_args = forward_args[1:]
    if not callable(target_main):
        raise ValueError("invalid wrapped CLI target")
    return int(target_main(forward_args))


def _add_forward_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],  # type: ignore[type-arg]
    *,
    name: str,
    help_text: str,
    target_main: Any,
) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    parser.set_defaults(handler=_cmd_forward, target_main=target_main, forward_args=[])


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aetherya",
        description="AETHERYA command-line interface.",
    )
    subparsers = parser.add_subparsers(dest="command")

    decide_parser = subparsers.add_parser(
        "decide",
        help="Evaluate one input through the deterministic policy pipeline.",
    )
    decide_parser.add_argument("raw_input", nargs="?", help="Raw user input to evaluate.")
    decide_parser.add_argument("--input", dest="inline_input", help="Raw input string.")
    decide_parser.add_argument("--actor", default="robert", help="Actor identity.")
    decide_parser.add_argument(
        "--policy-path", default="config/policy.yaml", help="Policy YAML path."
    )
    decide_parser.add_argument(
        "--constitution-path",
        default=None,
        help="Optional constitution YAML/JSON path. If omitted, built-in default is used.",
    )
    decide_parser.add_argument(
        "--audit-path",
        default=None,
        help="Optional audit JSONL path. If omitted, audit logging is disabled for this command.",
    )
    decide_parser.add_argument(
        "--candidate-response",
        default=None,
        help="Optional final response text to validate with OutputGate.",
    )
    shadow_group = decide_parser.add_mutually_exclusive_group()
    shadow_group.add_argument(
        "--wait-shadow",
        dest="wait_shadow",
        action="store_true",
        default=True,
        help="Wait for configured llm_shadow provider (default).",
    )
    shadow_group.add_argument(
        "--no-wait-shadow",
        dest="wait_shadow",
        action="store_false",
        help="Disable llm_shadow during this decide command for faster bulk runs.",
    )
    decide_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    decide_parser.set_defaults(handler=_cmd_decide)

    confirmation_parser = subparsers.add_parser("confirmation", help="Strong confirmation tooling.")
    confirmation_subparsers = confirmation_parser.add_subparsers(dest="confirmation_command")
    confirmation_subparsers.required = True

    confirmation_sign_parser = confirmation_subparsers.add_parser(
        "sign",
        help="Generate out-of-band approval proof for one operative action.",
    )
    confirmation_sign_parser.add_argument(
        "raw_input",
        nargs="?",
        help="Raw operative input to bind in approval proof scope.",
    )
    confirmation_sign_parser.add_argument("--input", dest="inline_input", help="Raw input string.")
    confirmation_sign_parser.add_argument("--actor", default="robert", help="Actor identity.")
    confirmation_sign_parser.add_argument(
        "--policy-path", default="config/policy.yaml", help="Policy YAML path."
    )
    confirmation_sign_parser.add_argument(
        "--key-env",
        default=None,
        help="Override env var name for HMAC key (defaults to policy signed_proof.key_env).",
    )
    confirmation_sign_parser.add_argument(
        "--expires-in-sec",
        type=int,
        default=None,
        help="Proof TTL in seconds (must be <= policy max_valid_for_sec).",
    )
    confirmation_sign_parser.add_argument(
        "--now-ts",
        type=int,
        default=None,
        help="Optional unix timestamp override for deterministic tests.",
    )
    confirmation_sign_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    confirmation_sign_parser.set_defaults(handler=_cmd_confirmation_sign)

    audit_parser = subparsers.add_parser("audit", help="Audit tooling.")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command")
    audit_subparsers.required = True
    _add_forward_command(
        audit_subparsers,
        name="verify",
        help_text="Verify audit integrity and attestation.",
        target_main=audit_verify_main,
    )

    explainability_parser = subparsers.add_parser("explainability", help="Explainability tooling.")
    explainability_subparsers = explainability_parser.add_subparsers(dest="explainability_command")
    explainability_subparsers.required = True
    _add_forward_command(
        explainability_subparsers,
        name="render",
        help_text="Render explainability Mermaid graph from audit.",
        target_main=explainability_render_main,
    )
    _add_forward_command(
        explainability_subparsers,
        name="report",
        help_text="Generate explainability HTML report from audit.",
        target_main=explainability_report_main,
    )

    security_parser = subparsers.add_parser("security", help="Security gate and baseline tooling.")
    security_subparsers = security_parser.add_subparsers(dest="security_command")
    security_subparsers.required = True
    _add_forward_command(
        security_subparsers,
        name="gate",
        help_text="Run 3-phase security gate.",
        target_main=security_gate_main,
    )
    _add_forward_command(
        security_subparsers,
        name="baseline",
        help_text="Run versioned security baseline regression.",
        target_main=security_baseline_main,
    )

    release_parser = subparsers.add_parser("release", help="Release readiness tooling.")
    release_subparsers = release_parser.add_subparsers(dest="release_command")
    release_subparsers.required = True
    _add_forward_command(
        release_subparsers,
        name="verify-artifacts",
        help_text="Verify release security artifacts and manifest.",
        target_main=verify_release_artifacts_main,
    )

    benchmark_parser = subparsers.add_parser("benchmark", help="Benchmark tooling.")
    benchmark_subparsers = benchmark_parser.add_subparsers(dest="benchmark_command")
    benchmark_subparsers.required = True
    _add_forward_command(
        benchmark_subparsers,
        name="pipeline",
        help_text="Run deterministic pipeline latency benchmark.",
        target_main=pipeline_benchmark_main,
    )
    _add_forward_command(
        benchmark_subparsers,
        name="chaos",
        help_text="Run chaos latency/detection benchmark.",
        target_main=chaos_benchmark_main,
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args, unknown = parser.parse_known_args(argv)
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        if code is None:
            return 1
        return 2

    handler = getattr(args, "handler", None)
    if not callable(handler):
        parser.print_help(sys.stderr)
        return 2

    if unknown:
        if handler is _cmd_forward:
            args.forward_args = [*list(getattr(args, "forward_args", [])), *unknown]
        else:
            print(f"error: unrecognized arguments: {' '.join(unknown)}", file=sys.stderr)
            return 2

    try:
        return int(handler(args))
    except Exception as exc:
        payload = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}
        if getattr(args, "json", False):
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        else:
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
