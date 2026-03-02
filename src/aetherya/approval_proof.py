from __future__ import annotations

import hashlib
import hmac
import json
import os
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
    kid: str
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


def _proof_message(*, kid: str, scope_hash: str, expires_at: int, nonce: str) -> str:
    return f"{_PROOF_VERSION}|{kid}|{expires_at}|{nonce}|{scope_hash}"


def _normalize_keyring(value: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for kid, secret in value.items():
        kid_clean = str(kid).strip().lower()
        secret_clean = str(secret).strip()
        if not kid_clean or not secret_clean:
            continue
        out[kid_clean] = secret_clean
    return out


def parse_approval_keyring(raw: str) -> dict[str, str]:
    text = raw.strip()
    if not text:
        return {}

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        return _normalize_keyring(parsed)

    out: dict[str, str] = {}
    for chunk in text.replace(";", ",").split(","):
        if not chunk.strip():
            continue
        if "=" not in chunk:
            raise ValueError("invalid keyring segment (expected kid=secret)")
        kid_raw, secret_raw = chunk.split("=", 1)
        kid = kid_raw.strip().lower()
        secret = secret_raw.strip()
        if not kid or not secret:
            raise ValueError("invalid keyring segment (kid and secret must be non-empty)")
        out[kid] = secret
    return out


def load_approval_keyring(
    *,
    keyring_env: str,
    fallback_env: str,
    fallback_kid: str,
) -> dict[str, str]:
    keyring_raw = os.getenv(keyring_env, "").strip()
    if keyring_raw:
        keyring = parse_approval_keyring(keyring_raw)
        if keyring:
            return keyring

    fallback_secret = os.getenv(fallback_env, "").strip()
    fallback_kid_clean = fallback_kid.strip().lower()
    if fallback_secret and fallback_kid_clean:
        return {fallback_kid_clean: fallback_secret}
    return {}


def build_approval_proof(
    *,
    secret: str,
    kid: str,
    actor: str,
    action: ActionRequest,
    ttl_sec: int,
    now_ts: int | None = None,
    nonce: str | None = None,
    exclude_params: set[str] | None = None,
) -> tuple[str, int]:
    if ttl_sec <= 0:
        raise ValueError("ttl_sec must be > 0")
    kid_clean = kid.strip().lower()
    if not kid_clean:
        raise ValueError("kid must be non-empty")
    if "." in kid_clean:
        raise ValueError("kid must not contain '.'")
    cleaned_secret = secret.strip()
    if not cleaned_secret:
        raise ValueError("secret must be non-empty")

    now = int(time.time()) if now_ts is None else int(now_ts)
    expires_at = now + int(ttl_sec)
    nonce_value = (
        nonce.strip().lower() if isinstance(nonce, str) and nonce.strip() else secrets.token_hex(8)
    )

    scope_hash = approval_scope_hash(actor=actor, action=action, exclude_params=exclude_params)
    message = _proof_message(
        kid=kid_clean,
        scope_hash=scope_hash,
        expires_at=expires_at,
        nonce=nonce_value,
    )
    signature = hmac.new(
        cleaned_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return (
        f"{_PROOF_VERSION}.{kid_clean}.{expires_at}.{nonce_value}.{scope_hash}.{signature}",
        expires_at,
    )


def _parse_approval_proof(proof: str) -> tuple[str, int, str, str, str]:
    parts = proof.strip().lower().split(".")
    if len(parts) != 6:
        raise ApprovalProofError("bad_format", "approval proof must have 6 dot-separated segments")
    version, kid, exp_raw, nonce, scope_hash, signature = parts
    if version != _PROOF_VERSION:
        raise ApprovalProofError("bad_version", "approval proof version is unsupported")
    if not kid:
        raise ApprovalProofError("bad_kid", "approval proof key id must be non-empty")
    try:
        expires_at = int(exp_raw)
    except ValueError as exc:
        raise ApprovalProofError("bad_expiry", "approval proof expiry must be int") from exc
    if expires_at <= 0:
        raise ApprovalProofError("bad_expiry", "approval proof expiry must be > 0")
    if not nonce:
        raise ApprovalProofError("bad_nonce", "approval proof nonce must be non-empty")
    if not scope_hash.startswith("sha256:") or len(scope_hash) <= len("sha256:"):
        raise ApprovalProofError("bad_scope_hash", "approval proof scope_hash is invalid")
    if len(signature) != 64:
        raise ApprovalProofError("bad_signature", "approval proof signature must be sha256 hex")
    return kid, expires_at, nonce, scope_hash, signature


def verify_approval_proof(
    *,
    keyring: Mapping[str, str] | None = None,
    secret: str = "",
    proof: str,
    actor: str,
    action: ActionRequest,
    now_ts: int | None = None,
    clock_skew_sec: int = 0,
    max_valid_for_sec: int = 900,
    exclude_params: set[str] | None = None,
) -> ApprovalProofVerification:
    if not proof.strip():
        raise ApprovalProofError("missing_proof", "approval proof is missing")
    if max_valid_for_sec <= 0:
        raise ApprovalProofError("invalid_window", "max_valid_for_sec must be > 0")
    if clock_skew_sec < 0:
        raise ApprovalProofError("invalid_window", "clock_skew_sec must be >= 0")

    kid, expires_at, nonce, scope_hash_claim, signature = _parse_approval_proof(proof)
    now = int(time.time()) if now_ts is None else int(now_ts)
    if now > (expires_at + clock_skew_sec):
        raise ApprovalProofError("expired", "approval proof has expired")
    if expires_at > (now + max_valid_for_sec + clock_skew_sec):
        raise ApprovalProofError(
            "window_too_large", "approval proof exceeds allowed validity window"
        )

    normalized_keyring = _normalize_keyring(keyring or {})
    if normalized_keyring:
        cleaned_secret = normalized_keyring.get(kid, "").strip()
        if not cleaned_secret:
            raise ApprovalProofError(
                "unknown_kid", "approval proof kid not found in verifier keyring"
            )
    else:
        cleaned_secret = secret.strip()
        if not cleaned_secret:
            raise ApprovalProofError("missing_secret", "approval verifier secret is missing")

    scope_hash = approval_scope_hash(actor=actor, action=action, exclude_params=exclude_params)
    if scope_hash_claim != scope_hash:
        raise ApprovalProofError("scope_mismatch", "approval proof scope_hash mismatch")

    expected = hmac.new(
        cleaned_secret.encode("utf-8"),
        _proof_message(
            kid=kid,
            scope_hash=scope_hash,
            expires_at=expires_at,
            nonce=nonce,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ApprovalProofError("invalid_signature", "approval proof signature mismatch")

    return ApprovalProofVerification(
        proof_version=_PROOF_VERSION,
        kid=kid,
        expires_at=expires_at,
        nonce=nonce,
        scope_hash=scope_hash,
    )
