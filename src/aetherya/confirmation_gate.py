from __future__ import annotations

import importlib
import os
import re
import threading
import time
from typing import Any, Protocol, TypedDict

from aetherya.actions import ActionRequest
from aetherya.approval_proof import (
    ApprovalProofError,
    load_approval_keyring,
    verify_approval_proof,
)
from aetherya.config import ConfirmationConfig
from aetherya.risk import RiskAggregate, RiskDecision


class ConfirmationOutcome(TypedDict, total=False):
    required: bool
    confirmed: bool
    reason: str
    tags: list[str]
    override_decision: str
    proof_required: bool
    proof_valid: bool
    proof_expires_at: int
    proof_scope_hash: str
    proof_kid: str


class _ReplayStore(Protocol):
    def check_and_mark(
        self,
        *,
        kid: str,
        nonce: str,
        scope_hash: str,
        expires_at: int,
        replay_mode: str,
    ) -> str: ...


class _InMemoryReplayStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], tuple[str, int]] = {}

    def _cleanup(self, now: int) -> None:
        stale = [key for key, (_, expires_at) in self._entries.items() if expires_at < now]
        for key in stale:
            self._entries.pop(key, None)

    def check_and_mark(
        self,
        *,
        kid: str,
        nonce: str,
        scope_hash: str,
        expires_at: int,
        replay_mode: str,
    ) -> str:
        now = int(time.time())
        key = (kid, nonce)
        with self._lock:
            self._cleanup(now)
            existing = self._entries.get(key)
            if existing is None:
                self._entries[key] = (scope_hash, expires_at)
                return "ok"

            existing_scope, existing_expiry = existing
            if replay_mode == "idempotent" and existing_scope == scope_hash:
                return "ok"
            if replay_mode == "idempotent":
                return "nonce_scope_mismatch"
            return "replay_detected"


class _RedisReplayStore:
    def __init__(self, client: Any, *, prefix: str = "aetherya:appr") -> None:
        self._client = client
        self._prefix = prefix.strip() or "aetherya:appr"

    def _decode_value(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    def _ttl(self, *, expires_at: int, now: int) -> int:
        ttl = int(expires_at) - int(now)
        return ttl if ttl > 0 else 1

    def check_and_mark(
        self,
        *,
        kid: str,
        nonce: str,
        scope_hash: str,
        expires_at: int,
        replay_mode: str,
    ) -> str:
        now = int(time.time())
        ttl = self._ttl(expires_at=int(expires_at), now=now)

        if replay_mode == "single_use":
            nonce_key = f"{self._prefix}:nonce:{kid}:{nonce}"
            created = bool(
                self._client.set(
                    nonce_key,
                    f"{scope_hash}|{expires_at}",
                    nx=True,
                    ex=ttl,
                )
            )
            return "ok" if created else "replay_detected"

        scope_key = f"{self._prefix}:scope:{scope_hash}"
        scope_value = f"{kid}|{nonce}|{expires_at}"
        created = bool(self._client.set(scope_key, scope_value, nx=True, ex=ttl))
        if created:
            return "ok"

        existing = self._decode_value(self._client.get(scope_key))
        chunks = existing.split("|")
        if len(chunks) >= 2 and chunks[0] == kid and chunks[1] == nonce:
            return "ok"
        return "nonce_scope_mismatch"


_REPLAY_STORE = _InMemoryReplayStore()
_REPLAY_STORES: dict[str, _ReplayStore] = {}
_REPLAY_STORES_LOCK = threading.Lock()


def _redis_client_from_url(url: str) -> Any:
    redis_module = importlib.import_module("redis")
    from_url = getattr(redis_module, "from_url", None)
    if callable(from_url):
        return from_url(url, decode_responses=True)

    redis_cls = getattr(redis_module, "Redis", None)
    if redis_cls is None:
        raise RuntimeError("redis module does not expose Redis client")
    from_url_method = getattr(redis_cls, "from_url", None)
    if not callable(from_url_method):
        raise RuntimeError("redis client does not support from_url")
    return from_url_method(url, decode_responses=True)


def _replay_store_from_config(cfg: ConfirmationConfig) -> _ReplayStore:
    signed_cfg = cfg.evidence.signed_proof
    if not signed_cfg.enabled:
        return _REPLAY_STORE
    if signed_cfg.replay_store == "memory":
        return _REPLAY_STORE

    redis_url = os.getenv(signed_cfg.replay_redis_url_env, "").strip()
    if not redis_url:
        raise RuntimeError(
            f"replay_store=redis but redis URL env is missing ({signed_cfg.replay_redis_url_env})"
        )

    cache_key = f"redis|{redis_url}|{signed_cfg.replay_redis_prefix}"
    with _REPLAY_STORES_LOCK:
        cached = _REPLAY_STORES.get(cache_key)
        if cached is not None:
            return cached

        client = _redis_client_from_url(redis_url)
        store = _RedisReplayStore(client, prefix=signed_cfg.replay_redis_prefix)
        _REPLAY_STORES[cache_key] = store
        return store


class ConfirmationGate:
    def __init__(
        self,
        cfg: ConfirmationConfig,
        *,
        replay_store: _ReplayStore | None = None,
    ) -> None:
        self.cfg = cfg
        self.replay_store = replay_store or _replay_store_from_config(cfg)

    def _requires_confirmation(self, action: ActionRequest, aggregate: RiskAggregate) -> bool:
        require = self.cfg.require_for
        if aggregate.decision.value in require.decisions:
            return True

        tool = (action.tool or "").strip().lower()
        if tool and tool in require.tools:
            return True

        op_raw = action.parameters.get("operation")
        operation = str(op_raw).strip().lower() if op_raw is not None else ""
        if operation and operation in require.operations:
            return True

        if aggregate.total_score >= require.min_risk_score and require.min_risk_score > 0:
            return True

        return False

    def _token_is_valid(self, token: str) -> bool:
        return re.fullmatch(self.cfg.evidence.token_pattern, token) is not None

    def evaluate(
        self, *, action: ActionRequest, aggregate: RiskAggregate, actor: str = "unknown"
    ) -> ConfirmationOutcome | None:
        if not self.cfg.enabled:
            return None

        if action.intent != "operate":
            return None

        if not self._requires_confirmation(action, aggregate):
            return None

        token_key = self.cfg.evidence.token_param
        context_key = self.cfg.evidence.context_param

        token_raw = action.parameters.get(token_key)
        context_raw = action.parameters.get(context_key)

        if token_raw is None or context_raw is None:
            return {
                "required": True,
                "confirmed": False,
                "reason": "strong confirmation evidence is missing",
                "tags": ["confirmation_required", "confirmation_missing"],
            }

        token = str(token_raw).strip().lower()
        context = str(context_raw).strip()

        if not self._token_is_valid(token):
            return {
                "required": True,
                "confirmed": False,
                "reason": "strong confirmation token is invalid",
                "tags": ["confirmation_required", "confirmation_invalid_token"],
            }

        if len(context) < self.cfg.evidence.min_context_length:
            return {
                "required": True,
                "confirmed": False,
                "reason": "strong confirmation context is too short",
                "tags": ["confirmation_required", "confirmation_context_too_short"],
            }

        signed_proof_cfg = self.cfg.evidence.signed_proof
        proof_expires_at: int | None = None
        proof_scope_hash: str | None = None
        proof_kid: str | None = None
        proof_tags: list[str] = []
        if signed_proof_cfg.enabled:
            proof_key = signed_proof_cfg.proof_param
            proof_raw = action.parameters.get(proof_key)
            if proof_raw is None or not str(proof_raw).strip():
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": "out-of-band approval proof is missing",
                    "tags": ["confirmation_required", "confirmation_proof_missing"],
                    "proof_required": True,
                    "proof_valid": False,
                }

            keyring = load_approval_keyring(
                keyring_env=signed_proof_cfg.keyring_env,
                fallback_env=signed_proof_cfg.key_env,
                fallback_kid=signed_proof_cfg.active_kid,
            )
            if not keyring:
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": "approval verifier keyring is not configured",
                    "tags": ["confirmation_required", "confirmation_proof_key_missing"],
                    "proof_required": True,
                    "proof_valid": False,
                }

            exclude_keys = {name for name in action.parameters if str(name).startswith("confirm_")}
            try:
                verification = verify_approval_proof(
                    keyring=keyring,
                    proof=str(proof_raw),
                    actor=str(actor),
                    action=action,
                    clock_skew_sec=signed_proof_cfg.clock_skew_sec,
                    max_valid_for_sec=signed_proof_cfg.max_valid_for_sec,
                    exclude_params=exclude_keys,
                )
            except ApprovalProofError as exc:
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": f"out-of-band approval proof is invalid ({exc.code})",
                    "tags": [
                        "confirmation_required",
                        "confirmation_proof_invalid",
                        f"confirmation_proof_{exc.code}",
                    ],
                    "proof_required": True,
                    "proof_valid": False,
                }

            replay_result = self.replay_store.check_and_mark(
                kid=verification.kid,
                nonce=verification.nonce,
                scope_hash=verification.scope_hash,
                expires_at=verification.expires_at + signed_proof_cfg.clock_skew_sec,
                replay_mode=signed_proof_cfg.replay_mode,
            )
            if replay_result != "ok":
                return {
                    "required": True,
                    "confirmed": False,
                    "reason": f"out-of-band approval proof replay rejected ({replay_result})",
                    "tags": [
                        "confirmation_required",
                        "confirmation_proof_replay_rejected",
                        f"confirmation_proof_{replay_result}",
                    ],
                    "proof_required": True,
                    "proof_valid": False,
                }

            proof_expires_at = verification.expires_at
            proof_scope_hash = verification.scope_hash
            proof_kid = verification.kid
            proof_tags.append("confirmation_proof_validated")
            proof_tags.append("confirmation_proof_replay_checked")

        outcome: ConfirmationOutcome = {
            "required": True,
            "confirmed": True,
            "reason": "strong confirmation validated",
            "tags": ["confirmation_validated", *proof_tags],
        }
        if signed_proof_cfg.enabled:
            outcome["proof_required"] = True
            outcome["proof_valid"] = True
        if proof_expires_at is not None:
            outcome["proof_expires_at"] = int(proof_expires_at)
        if proof_scope_hash is not None:
            outcome["proof_scope_hash"] = str(proof_scope_hash)
        if proof_kid is not None:
            outcome["proof_kid"] = str(proof_kid)

        if aggregate.decision == RiskDecision.REQUIRE_CONFIRM:
            outcome["override_decision"] = self.cfg.on_confirmed

        return outcome
