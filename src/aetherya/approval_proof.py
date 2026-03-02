from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aetherya.actions import ActionRequest

_PROOF_VERSION = "ap1"


class ApprovalProofError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ApprovalProofVerification:
    proof_version: str
    expires_at: int
    nonce: str
    scope_hash: str


def _stable_value(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {
            str(k): _stable_value(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list):
        return [_stable_value(item) for item in value]
    if isinstance(value, tuple):
        return [_stable_value(item) for item in value]
    return str(value)


def _scope_payload(
    *,
    actor: str,
    action: ActionRequest,
    exclude_params: set[str] | None = None,
) -> dict[str, Any]:
    excluded = exclude_params or set()
    normalized_params: dict[str, Any] = {}
    for key, value in action.parameters.items():
        key_str = str(key)
        if key_str in excluded:
            continue
        normalized_params[key_str] = _stable_value(value)

    op_raw = action.parameters.get("operation")
    operation = str(op_raw).strip().lower() if op_raw is not None else ""

    return {
        "actor": actor,
        "intent": action.intent,
        "mode_hint": action.mode_hint or "",
        "tool": action.tool or "",
        "target": action.target or "",
        "operation": operation,
        "parameters": normalized_params,
    }


def approval_scope_hash(
    *,
    actor: str,
    action: ActionRequest,
    exclude_params: set[str] | None = None,
) -> str:
    payload = _scope_payload(actor=actor, action=action, exclude_params=exclude_params)
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _proof_message(*, scope_hash: str, expires_at: int, nonce: str) -> str:
    return f"{_PROOF_VERSION}|{expires_at}|{nonce}|{scope_hash}"


def build_approval_proof(
    *,
    secret: str,
    actor: str,
    action: ActionRequest,
    ttl_sec: int,
    now_ts: int | None = None,
    nonce: str | None = None,
    exclude_params: set[str] | None = None,
) -> tuple[str, int]:
    if ttl_sec <= 0:
        raise ValueError("ttl_sec must be > 0")
    cleaned_secret = secret.strip()
    if not cleaned_secret:
        raise ValueError("secret must be non-empty")

    now = int(time.time()) if now_ts is None else int(now_ts)
    expires_at = now + int(ttl_sec)
    nonce_value = (
        nonce.strip().lower() if isinstance(nonce, str) and nonce.strip() else secrets.token_hex(8)
    )

    scope_hash = approval_scope_hash(actor=actor, action=action, exclude_params=exclude_params)
    message = _proof_message(scope_hash=scope_hash, expires_at=expires_at, nonce=nonce_value)
    signature = hmac.new(
        cleaned_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return (f"{_PROOF_VERSION}.{expires_at}.{nonce_value}.{signature}", expires_at)


def _parse_approval_proof(proof: str) -> tuple[int, str, str]:
    parts = proof.strip().lower().split(".")
    if len(parts) != 4:
        raise ApprovalProofError("bad_format", "approval proof must have 4 dot-separated segments")
    version, exp_raw, nonce, signature = parts
    if version != _PROOF_VERSION:
        raise ApprovalProofError("bad_version", "approval proof version is unsupported")
    try:
        expires_at = int(exp_raw)
    except ValueError as exc:
        raise ApprovalProofError("bad_expiry", "approval proof expiry must be int") from exc
    if expires_at <= 0:
        raise ApprovalProofError("bad_expiry", "approval proof expiry must be > 0")
    if not nonce:
        raise ApprovalProofError("bad_nonce", "approval proof nonce must be non-empty")
    if len(signature) != 64:
        raise ApprovalProofError("bad_signature", "approval proof signature must be sha256 hex")
    return expires_at, nonce, signature


def verify_approval_proof(
    *,
    secret: str,
    proof: str,
    actor: str,
    action: ActionRequest,
    now_ts: int | None = None,
    clock_skew_sec: int = 0,
    max_valid_for_sec: int = 900,
    exclude_params: set[str] | None = None,
) -> ApprovalProofVerification:
    cleaned_secret = secret.strip()
    if not cleaned_secret:
        raise ApprovalProofError("missing_secret", "approval verifier secret is missing")
    if not proof.strip():
        raise ApprovalProofError("missing_proof", "approval proof is missing")
    if max_valid_for_sec <= 0:
        raise ApprovalProofError("invalid_window", "max_valid_for_sec must be > 0")
    if clock_skew_sec < 0:
        raise ApprovalProofError("invalid_window", "clock_skew_sec must be >= 0")

    expires_at, nonce, signature = _parse_approval_proof(proof)
    now = int(time.time()) if now_ts is None else int(now_ts)
    if now > (expires_at + clock_skew_sec):
        raise ApprovalProofError("expired", "approval proof has expired")
    if expires_at > (now + max_valid_for_sec + clock_skew_sec):
        raise ApprovalProofError(
            "window_too_large", "approval proof exceeds allowed validity window"
        )

    scope_hash = approval_scope_hash(actor=actor, action=action, exclude_params=exclude_params)
    expected = hmac.new(
        cleaned_secret.encode("utf-8"),
        _proof_message(scope_hash=scope_hash, expires_at=expires_at, nonce=nonce).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ApprovalProofError("invalid_signature", "approval proof signature mismatch")

    return ApprovalProofVerification(
        proof_version=_PROOF_VERSION,
        expires_at=expires_at,
        nonce=nonce,
        scope_hash=scope_hash,
    )
