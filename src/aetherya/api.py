from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aetherya.actions import validate_action_request, validate_actor
from aetherya.approval_proof import (
    approval_scope_hash,
    build_approval_proof,
    load_approval_keyring,
    verify_approval_proof,
)
from aetherya.audit import AuditLogger
from aetherya.audit_verify import _build_report, verify_audit_file
from aetherya.cli import (
    _default_constitution,
    _llm_shadow_disabled,
    _load_constitution,
    _maybe_read_last_event,
)
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution
from aetherya.parser import parse_user_input
from aetherya.pipeline import run_pipeline


@dataclass(frozen=True)
class APISettings:
    policy_path: Path = Path("config/policy.yaml")
    audit_path: Path | None = Path("audit/decisions.jsonl")
    constitution_path: Path | None = None
    default_actor: str = "robert"
    approval_admin_key_env: str = "AETHERYA_APPROVALS_API_KEY"
    approval_sign_local_only: bool = True


def _as_mapping(payload: Any, *, field_name: str) -> dict[str, Any]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return payload


def _as_non_empty_str(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be str")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must be non-empty")
    return cleaned


def _as_bool(value: Any, *, field_name: str, default: bool) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    raise ValueError(f"{field_name} must be bool")


def _as_optional_int(value: Any, *, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be int")
    if isinstance(value, int):
        return value
    raise ValueError(f"{field_name} must be int")


def _as_optional_str(value: Any, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be str")
    cleaned = value.strip()
    return cleaned if cleaned else None


def _header_value(headers: dict[str, Any] | None, key: str) -> str:
    if not headers:
        return ""
    target = key.strip().lower()
    for raw_key, raw_value in headers.items():
        if str(raw_key).strip().lower() == target:
            return str(raw_value).strip()
    return ""


class AetheryaAPI:
    def __init__(self, settings: APISettings | None = None):
        self.settings = settings or APISettings()

    def _resolve_constitution(self) -> Constitution:
        path = self.settings.constitution_path
        if path is None:
            return _default_constitution()
        return _load_constitution(path)

    def _authorize_admin(
        self,
        *,
        headers: dict[str, Any] | None,
        client_ip: str | None,
    ) -> tuple[int, dict[str, Any]] | None:
        if self.settings.approval_sign_local_only and client_ip not in {"127.0.0.1", "::1"}:
            return (
                403,
                {
                    "ok": False,
                    "error_type": "Forbidden",
                    "error": "confirmation admin routes are localhost-only",
                },
            )

        expected_key = os.getenv(self.settings.approval_admin_key_env, "").strip()
        if not expected_key:
            return (
                503,
                {
                    "ok": False,
                    "error_type": "ServiceUnavailable",
                    "error": (
                        "approval admin key is not configured "
                        f"({self.settings.approval_admin_key_env})"
                    ),
                },
            )

        provided_key = _header_value(headers, "x-aetherya-admin-key")
        if not provided_key or not hmac.compare_digest(provided_key, expected_key):
            return (
                401,
                {
                    "ok": False,
                    "error_type": "Unauthorized",
                    "error": "missing or invalid admin key for confirmation route",
                },
            )
        return None

    def health(self) -> tuple[int, dict[str, Any]]:
        try:
            cfg = load_policy_config(self.settings.policy_path)
            _ = self._resolve_constitution()
        except Exception as exc:
            return (
                503,
                {
                    "ok": False,
                    "service": "aetherya-api",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

        return (
            200,
            {
                "ok": True,
                "service": "aetherya-api",
                "policy_path": str(self.settings.policy_path),
                "policy_fingerprint": cfg.policy_fingerprint,
                "audit_path": str(self.settings.audit_path) if self.settings.audit_path else None,
                "default_actor": self.settings.default_actor,
            },
        )

    def decide(self, payload: Any) -> tuple[int, dict[str, Any]]:
        try:
            body = _as_mapping(payload, field_name="decide payload")
            raw_input = _as_non_empty_str(body.get("raw_input"), field_name="raw_input")
            actor = _as_non_empty_str(
                body.get("actor", self.settings.default_actor),
                field_name="actor",
            )
            wait_shadow = _as_bool(
                body.get("wait_shadow"),
                field_name="wait_shadow",
                default=True,
            )
            candidate_response = _as_optional_str(
                body.get("candidate_response"),
                field_name="candidate_response",
            )

            cfg = load_policy_config(self.settings.policy_path)
            cfg_effective = _llm_shadow_disabled(cfg, wait_shadow=wait_shadow)
            constitution = self._resolve_constitution()
            audit_path = self.settings.audit_path
            audit = AuditLogger(str(audit_path)) if audit_path is not None else None

            decision = run_pipeline(
                raw_input,
                constitution=constitution,
                actor=actor,
                cfg=cfg_effective,
                audit=audit,
                response_text=candidate_response,
            )

            event = _maybe_read_last_event(audit_path) if audit_path is not None else None
            return (
                200,
                {
                    "ok": True,
                    "decision": decision.to_dict(),
                    "meta": {
                        "actor": actor,
                        "wait_shadow": wait_shadow,
                        "policy_path": str(self.settings.policy_path),
                        "constitution_path": (
                            str(self.settings.constitution_path)
                            if self.settings.constitution_path is not None
                            else None
                        ),
                        "audit_path": str(audit_path) if audit_path is not None else None,
                        "policy_fingerprint": cfg.policy_fingerprint,
                        "llm_shadow_enabled_config": bool(cfg.llm_shadow.enabled),
                        "llm_shadow_enabled_effective": bool(cfg_effective.llm_shadow.enabled),
                        "candidate_response_present": candidate_response is not None,
                        "event_id": event.get("event_id") if isinstance(event, dict) else None,
                        "decision_id": (
                            event.get("decision_id") if isinstance(event, dict) else None
                        ),
                    },
                },
            )
        except ValueError as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )
        except Exception as exc:
            return (
                500,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def audit_verify(self, payload: Any) -> tuple[int, dict[str, Any]]:
        try:
            body = _as_mapping(payload, field_name="audit verify payload")
            if self.settings.audit_path is None:
                raise ValueError("audit_path is disabled in API settings")

            event_index = _as_optional_int(body.get("event_index"), field_name="event_index")
            attestation_key = _as_optional_str(
                body.get("attestation_key"),
                field_name="attestation_key",
            )
            require_hmac = _as_bool(
                body.get("require_hmac"),
                field_name="require_hmac",
                default=False,
            )
            require_chain = _as_bool(
                body.get("require_chain"),
                field_name="require_chain",
                default=False,
            )

            records = verify_audit_file(
                self.settings.audit_path,
                event_index=event_index,
                attestation_key=attestation_key,
                require_hmac=require_hmac,
                require_chain=require_chain,
            )
            report = _build_report(
                records=records,
                audit_path=self.settings.audit_path,
                event_index=event_index,
                require_hmac=require_hmac,
                require_chain=require_chain,
            )
            ok = int(report["invalid"]) == 0
            return (200, {"ok": ok, "report": report})
        except ValueError as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )
        except Exception as exc:
            return (
                500,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def confirmation_sign(
        self,
        payload: Any,
        *,
        headers: dict[str, Any] | None,
        client_ip: str | None,
    ) -> tuple[int, dict[str, Any]]:
        auth_error = self._authorize_admin(headers=headers, client_ip=client_ip)
        if auth_error is not None:
            return auth_error
        try:
            body = _as_mapping(payload, field_name="confirmation sign payload")
            raw_input = _as_non_empty_str(body.get("raw_input"), field_name="raw_input")
            actor = validate_actor(
                _as_non_empty_str(
                    body.get("actor", self.settings.default_actor),
                    field_name="actor",
                )
            )
            expires_in_sec = _as_optional_int(
                body.get("expires_in_sec"), field_name="expires_in_sec"
            )
            now_ts = _as_optional_int(body.get("now_ts"), field_name="now_ts")

            cfg = load_policy_config(self.settings.policy_path)
            signed_cfg = cfg.confirmation.evidence.signed_proof
            if not signed_cfg.enabled:
                raise ValueError(
                    "confirmation.evidence.signed_proof.enabled=false in current policy"
                )

            ttl = (
                int(expires_in_sec) if expires_in_sec is not None else signed_cfg.max_valid_for_sec
            )
            if ttl <= 0:
                raise ValueError("expires_in_sec must be > 0")
            if ttl > signed_cfg.max_valid_for_sec:
                raise ValueError(
                    f"expires_in_sec exceeds policy max_valid_for_sec ({signed_cfg.max_valid_for_sec})"
                )

            action = validate_action_request(parse_user_input(raw_input))
            if action.intent != "operate":
                raise ValueError("confirmation sign requires an operative action input")
            excluded = {name for name in action.parameters if str(name).startswith("confirm_")}

            keyring = load_approval_keyring(
                keyring_env=signed_cfg.keyring_env,
                fallback_env=signed_cfg.key_env,
                fallback_kid=signed_cfg.active_kid,
            )
            secret = keyring.get(signed_cfg.active_kid, "").strip()
            if not secret:
                raise RuntimeError(
                    "missing approval signing key for active kid "
                    f"'{signed_cfg.active_kid}' in env vars: "
                    f"{signed_cfg.keyring_env} or {signed_cfg.key_env}"
                )

            proof, expires_at = build_approval_proof(
                secret=secret,
                kid=signed_cfg.active_kid,
                actor=actor,
                action=action,
                ttl_sec=ttl,
                now_ts=now_ts,
                exclude_params=excluded,
            )
            scope_hash = approval_scope_hash(actor=actor, action=action, exclude_params=excluded)
            return (
                200,
                {
                    "ok": True,
                    "approval_proof": proof,
                    "proof_param": signed_cfg.proof_param,
                    "kid": signed_cfg.active_kid,
                    "expires_at": int(expires_at),
                    "expires_in_sec": int(ttl),
                    "scope_hash": scope_hash,
                    "actor": actor,
                    "operation": action.parameters.get("operation"),
                    "tool": action.tool,
                    "target": action.target,
                    "replay_mode": signed_cfg.replay_mode,
                    "policy_path": str(self.settings.policy_path),
                },
            )
        except ValueError as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )
        except Exception as exc:
            return (
                500,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def confirmation_verify(
        self,
        payload: Any,
        *,
        headers: dict[str, Any] | None,
        client_ip: str | None,
    ) -> tuple[int, dict[str, Any]]:
        auth_error = self._authorize_admin(headers=headers, client_ip=client_ip)
        if auth_error is not None:
            return auth_error
        try:
            body = _as_mapping(payload, field_name="confirmation verify payload")
            raw_input = _as_non_empty_str(body.get("raw_input"), field_name="raw_input")
            actor = validate_actor(
                _as_non_empty_str(
                    body.get("actor", self.settings.default_actor),
                    field_name="actor",
                )
            )
            approval_proof = _as_non_empty_str(
                body.get("approval_proof"), field_name="approval_proof"
            )
            now_ts = _as_optional_int(body.get("now_ts"), field_name="now_ts")

            cfg = load_policy_config(self.settings.policy_path)
            signed_cfg = cfg.confirmation.evidence.signed_proof
            if not signed_cfg.enabled:
                raise ValueError(
                    "confirmation.evidence.signed_proof.enabled=false in current policy"
                )

            action = validate_action_request(parse_user_input(raw_input))
            if action.intent != "operate":
                raise ValueError("confirmation verify requires an operative action input")

            keyring = load_approval_keyring(
                keyring_env=signed_cfg.keyring_env,
                fallback_env=signed_cfg.key_env,
                fallback_kid=signed_cfg.active_kid,
            )
            if not keyring:
                raise RuntimeError(
                    "approval verifier keyring is not configured "
                    f"({signed_cfg.keyring_env} or {signed_cfg.key_env})"
                )

            excluded = {name for name in action.parameters if str(name).startswith("confirm_")}
            verification = verify_approval_proof(
                keyring=keyring,
                proof=approval_proof,
                actor=actor,
                action=action,
                now_ts=now_ts,
                clock_skew_sec=signed_cfg.clock_skew_sec,
                max_valid_for_sec=signed_cfg.max_valid_for_sec,
                exclude_params=excluded,
            )
            return (
                200,
                {
                    "ok": True,
                    "valid": True,
                    "proof_version": verification.proof_version,
                    "kid": verification.kid,
                    "expires_at": int(verification.expires_at),
                    "nonce": verification.nonce,
                    "scope_hash": verification.scope_hash,
                },
            )
        except ValueError as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )
        except Exception as exc:
            return (
                500,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def dispatch(
        self,
        method: str,
        path: str,
        payload: Any = None,
        *,
        headers: dict[str, Any] | None = None,
        client_ip: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if method == "GET" and path == "/health":
            return self.health()
        if path == "/v1/decide":
            if method == "POST":
                return self.decide(payload)
            return (
                405,
                {
                    "ok": False,
                    "error_type": "MethodNotAllowed",
                    "error": "method not allowed for /v1/decide",
                    "allowed_methods": ["POST"],
                },
            )
        if path == "/v1/audit/verify":
            if method == "POST":
                return self.audit_verify(payload)
            return (
                405,
                {
                    "ok": False,
                    "error_type": "MethodNotAllowed",
                    "error": "method not allowed for /v1/audit/verify",
                    "allowed_methods": ["POST"],
                },
            )
        if path == "/v1/confirmation/sign":
            if method == "POST":
                return self.confirmation_sign(payload, headers=headers, client_ip=client_ip)
            return (
                405,
                {
                    "ok": False,
                    "error_type": "MethodNotAllowed",
                    "error": "method not allowed for /v1/confirmation/sign",
                    "allowed_methods": ["POST"],
                },
            )
        if path == "/v1/confirmation/verify":
            if method == "POST":
                return self.confirmation_verify(payload, headers=headers, client_ip=client_ip)
            return (
                405,
                {
                    "ok": False,
                    "error_type": "MethodNotAllowed",
                    "error": "method not allowed for /v1/confirmation/verify",
                    "allowed_methods": ["POST"],
                },
            )
        return (
            404,
            {
                "ok": False,
                "error_type": "NotFound",
                "error": f"route not found: {method} {path}",
            },
        )
