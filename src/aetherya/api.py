from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
from aetherya.pipeline import run_pipeline


@dataclass(frozen=True)
class APISettings:
    policy_path: Path = Path("config/policy.yaml")
    audit_path: Path | None = Path("audit/decisions.jsonl")
    constitution_path: Path | None = None
    default_actor: str = "robert"


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


class AetheryaAPI:
    def __init__(self, settings: APISettings | None = None):
        self.settings = settings or APISettings()

    def _resolve_constitution(self) -> Constitution:
        path = self.settings.constitution_path
        if path is None:
            return _default_constitution()
        return _load_constitution(path)

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

    def dispatch(self, method: str, path: str, payload: Any = None) -> tuple[int, dict[str, Any]]:
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
        return (
            404,
            {
                "ok": False,
                "error_type": "NotFound",
                "error": f"route not found: {method} {path}",
            },
        )
