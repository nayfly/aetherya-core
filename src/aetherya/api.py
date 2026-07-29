from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aetherya.actions import ActionRequest, validate_action_request, validate_actor
from aetherya.approval_proof import (
    approval_scope_hash,
    build_approval_proof,
    load_approval_keyring,
    verify_approval_proof,
)
from aetherya.audit import AuditLogger
from aetherya.audit_sink import mirror_health
from aetherya.audit_verify import _build_report, verify_audit_file
from aetherya.cli import (
    _default_constitution,
    _llm_shadow_disabled,
    _load_constitution,
    _maybe_read_last_event,
)
from aetherya.config import expected_policy_fingerprint, load_policy_config
from aetherya.constitution import Constitution, is_model_warm
from aetherya.parser import parse_user_input
from aetherya.pipeline import run_pipeline
from aetherya.rate_limiter import RateLimitConfig, RateLimiter, build_rate_limiter
from aetherya.review_store import ReviewStore
from aetherya.rollout_report import DEFAULT_MIN_DAYS, DEFAULT_MIN_DECISIONS, build_report


@dataclass(frozen=True)
class APISettings:
    policy_path: Path = Path("config/policy.yaml")
    audit_path: Path | None = Path("audit/decisions.jsonl")
    constitution_path: Path | None = None
    default_actor: str = "robert"
    service_name: str = "aetherya-api"
    enable_decide_routes: bool = True
    enable_audit_routes: bool = True
    enable_approval_routes: bool = True
    approval_admin_key_env: str = "AETHERYA_APPROVALS_API_KEY"
    approval_sign_local_only: bool = True
    review_path: Path | None = Path("audit/reviews.jsonl")


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


def _as_action_request(value: Any) -> ActionRequest:
    """
    Build an ActionRequest from an explicit `action` object.

    This is the structured entry point: the caller declares intent, tool, target
    and parameters instead of leaving them to be inferred from free text. Every
    field is validated against the ABI contract before it reaches the pipeline.
    """
    body = _as_mapping(value, field_name="action")
    raw_input = _as_non_empty_str(body.get("raw_input"), field_name="action.raw_input")
    intent = _as_non_empty_str(body.get("intent"), field_name="action.intent")

    raw_parameters = body.get("parameters", {})
    if raw_parameters is None:
        raw_parameters = {}
    parameters = _as_mapping(raw_parameters, field_name="action.parameters")
    for key in parameters:
        if not isinstance(key, str):
            raise ValueError("action.parameters keys must be str")

    return validate_action_request(
        ActionRequest(
            raw_input=raw_input,
            intent=intent,
            mode_hint=_as_optional_str(body.get("mode_hint"), field_name="action.mode_hint"),
            tool=_as_optional_str(body.get("tool"), field_name="action.tool"),
            target=_as_optional_str(body.get("target"), field_name="action.target"),
            parameters=dict(parameters),
        )
    )


# Env vars holding secrets that a console field must never be allowed to carry.
_SECRET_ENVS: tuple[str, ...] = (
    "AETHERYA_CONSOLE_API_KEY",
    "AETHERYA_APPROVALS_API_KEY",
    "AETHERYA_CONFIRMATION_HMAC_KEY",
    "AETHERYA_ATTESTATION_KEY",
)


def _reject_credentials(**fields: str) -> None:
    """
    Refuse free-text that contains one of this process's secrets.

    The console asks for a key and then, in an identical prompt, for a reviewer
    name — so pasting the key into the name is the obvious mistake, and it
    writes the credential in plaintext into the audit trail, which is exported,
    mirrored and archived. A field the operator types must never be able to put
    a secret somewhere it cannot be taken back out of.
    """
    secrets = {
        value
        for env in _SECRET_ENVS
        # Short values would match ordinary prose; a real key never is.
        if len(value := os.getenv(env, "").strip()) >= 8
    }
    for name, supplied in fields.items():
        if any(secret in supplied for secret in secrets):
            raise ValueError(
                f"{name} contains a credential — it would be written to the audit "
                f"trail in plaintext. Use your own name, not the console key."
            )


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
        # Built once and reused: the in-process backend keeps its windows on the
        # instance, so rebuilding per request would reset every limit and make
        # the limiter a no-op. Rebuilt only if the policy's rate-limit section
        # changes underneath us.
        self._rate_limiter: RateLimiter | None = None
        self._rate_limiter_key: tuple[Any, ...] | None = None

    def _resolve_rate_limiter(self, cfg: Any) -> RateLimiter | None:
        rl = getattr(cfg, "rate_limit", None)
        if rl is None:
            return None

        key = (
            rl.backend,
            rl.requests_per_window,
            rl.window_seconds,
            rl.max_actors,
            rl.redis_url_env,
            rl.redis_prefix,
        )
        if self._rate_limiter is not None and self._rate_limiter_key == key:
            return self._rate_limiter

        limiter = build_rate_limiter(
            rl.backend,
            RateLimitConfig(
                requests_per_window=rl.requests_per_window,
                window_seconds=rl.window_seconds,
                max_actors=rl.max_actors,
            ),
            redis_url_env=rl.redis_url_env,
            redis_prefix=rl.redis_prefix,
        )
        self._rate_limiter = limiter
        self._rate_limiter_key = key
        return limiter

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
                    "service": self.settings.service_name,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

        pinned = expected_policy_fingerprint()
        semantic_enabled = cfg.constitution_config.use_semantic
        semantic_warm = is_model_warm()
        # With `require_warm_semantic_model` the advisory layer silently declines
        # to run until the model is loaded. Reporting that here is what keeps it
        # from being a silent no-op in production: an operator can see whether the
        # layer they configured is actually participating in decisions.
        semantic_ready = (
            (not semantic_enabled)
            or semantic_warm
            or (not cfg.constitution_config.require_warm_semantic_model)
        )

        degraded = semantic_enabled and not semantic_ready
        return (
            200,
            {
                "ok": True,
                "service": self.settings.service_name,
                "policy_path": str(self.settings.policy_path),
                # `policy_fingerprint` is the file's bytes (provenance);
                # `effective_fingerprint` is the behavioural identity and is what
                # the pin is checked against.
                "policy_fingerprint": cfg.policy_fingerprint,
                "effective_fingerprint": cfg.effective_fingerprint,
                "policy_fingerprint_pinned": pinned,
                "policy_fingerprint_match": (pinned is None or pinned == cfg.effective_fingerprint),
                "semantic_enabled": semantic_enabled,
                "semantic_ready": semantic_ready,
                "semantic_model_warm": semantic_warm,
                "degraded": degraded,
                "audit_path": str(self.settings.audit_path) if self.settings.audit_path else None,
                "default_actor": self.settings.default_actor,
                **mirror_health(),
            },
        )

    def decide(self, payload: Any) -> tuple[int, dict[str, Any]]:
        try:
            body = _as_mapping(payload, field_name="decide payload")

            # Two input shapes. `action` is the structured, preferred one: the
            # caller declares intent/tool/target/parameters, so no part of the
            # decision depends on inferring structure from free text.
            # `raw_input` keeps the free-text path for callers that only have text.
            action: ActionRequest | None = None
            raw_action = body.get("action")
            if raw_action is not None:
                action = _as_action_request(raw_action)
                raw_input = action.raw_input
            else:
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
                action=action,
                rate_limiter=self._resolve_rate_limiter(cfg_effective),
            )

            event = _maybe_read_last_event(audit_path) if audit_path is not None else None
            return (
                200,
                {
                    "ok": True,
                    "decision": decision.to_dict(),
                    "meta": {
                        "actor": actor,
                        "input_mode": "structured" if action is not None else "raw_text",
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

    def decisions(self, params: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        """
        Recent decisions from the audit trail, newest first.

        Read-only view for the operator console. Reads the tail of the file
        rather than holding an index: at console volumes that is simpler and
        cannot drift from the authoritative record, which is the file itself.
        """
        try:
            query = params or {}
            if self.settings.audit_path is None:
                raise ValueError("audit_path is disabled in API settings")

            limit = max(1, min(int(query.get("limit", 100) or 100), 1000))
            state_filter = _as_optional_str(query.get("state"), field_name="state")

            events: list[dict[str, Any]] = []
            path = self.settings.audit_path
            lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
            for raw in reversed(lines):
                if len(events) >= limit:
                    break
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                decision = event.get("decision") or {}
                state = str(decision.get("state", "unknown"))
                if state_filter and state != state_filter:
                    continue
                context = event.get("context") or {}
                action_ctx = context.get("action") if isinstance(context, dict) else {}
                events.append(
                    {
                        "ts": event.get("ts"),
                        "actor": event.get("actor"),
                        "action": str(event.get("action", ""))[:400],
                        "state": state,
                        "allowed": decision.get("allowed"),
                        "risk_score": decision.get("risk_score"),
                        "reason": decision.get("reason"),
                        "violated_principle": decision.get("violated_principle"),
                        "tool": (action_ctx.get("tool") if isinstance(action_ctx, dict) else None),
                        "escalated": bool(
                            isinstance(context, dict) and context.get("intent_escalation")
                        ),
                        "decision_id": event.get("decision_id"),
                    }
                )

            return (200, {"ok": True, "count": len(events), "decisions": events})
        except Exception as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def record_review(self, payload: Any) -> tuple[int, dict[str, Any]]:
        """
        Record a human verdict on one hard_deny event.

        This is the only write the console makes, and it is the thing that
        unblocks `hard_deny_reviewed`. The event is looked up in the audit
        trail first: a verdict on an id that is not a hard_deny would be
        recorded, counted by nothing, and leave the operator believing they had
        reviewed something.
        """
        try:
            body = _as_mapping(payload, field_name="review payload")
            if self.settings.review_path is None:
                raise ValueError("review_path is disabled in API settings")
            if self.settings.audit_path is None:
                raise ValueError("audit_path is disabled in API settings")

            event_id = _as_non_empty_str(body.get("event_id"), field_name="event_id")
            verdict = _as_non_empty_str(body.get("verdict"), field_name="verdict")
            reviewer = _as_non_empty_str(body.get("reviewer"), field_name="reviewer")
            note = str(body.get("note") or "")

            _reject_credentials(reviewer=reviewer, note=note)

            state = self._state_of_event(event_id)
            if state is None:
                raise ValueError(f"no audit event with event_id {event_id!r}")
            if state != "hard_deny":
                raise ValueError(f"event {event_id!r} is `{state}`, not `hard_deny`")

            review = ReviewStore(self.settings.review_path).record(
                event_id,
                verdict,
                reviewer=reviewer,
                note=note,
            )
            return (200, {"ok": True, "review": review.to_dict()})
        except Exception as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def reviews(self) -> tuple[int, dict[str, Any]]:
        """Every recorded verdict, newest first, including superseded ones."""
        try:
            if self.settings.review_path is None:
                raise ValueError("review_path is disabled in API settings")
            history = ReviewStore(self.settings.review_path).history()
            return (
                200,
                {
                    "ok": True,
                    "count": len(history),
                    "reviews": [r.to_dict() for r in reversed(history)],
                },
            )
        except Exception as exc:
            return (
                400,
                {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
            )

    def _state_of_event(self, event_id: str) -> str | None:
        path = self.settings.audit_path
        if path is None or not Path(path).exists():
            return None
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and str(event.get("event_id", "")) == event_id:
                decision = event.get("decision")
                if isinstance(decision, dict):
                    return str(decision.get("state", "unknown"))
                return "unknown"
        return None

    def rollout(self, params: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        """Phase measurement for the console — same data as `aetherya rollout report`."""
        try:
            query = params or {}
            if self.settings.audit_path is None:
                raise ValueError("audit_path is disabled in API settings")

            cfg = load_policy_config(self.settings.policy_path)
            phase = int(query.get("phase") or cfg.enforcement.phase)
            report = build_report(
                self.settings.audit_path,
                current_phase=phase,
                min_decisions=int(query.get("min_decisions", DEFAULT_MIN_DECISIONS) or 0)
                or DEFAULT_MIN_DECISIONS,
                min_days=float(query.get("min_days", DEFAULT_MIN_DAYS) or 0) or DEFAULT_MIN_DAYS,
                review_path=self.settings.review_path,
            )
            return (200, {"ok": True, "report": report.to_dict()})
        except Exception as exc:
            return (
                400,
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
            if not self.settings.enable_decide_routes:
                return (
                    404,
                    {
                        "ok": False,
                        "error_type": "NotFound",
                        "error": f"route not found: {method} {path}",
                    },
                )
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
            if not self.settings.enable_audit_routes:
                return (
                    404,
                    {
                        "ok": False,
                        "error_type": "NotFound",
                        "error": f"route not found: {method} {path}",
                    },
                )
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
            if not self.settings.enable_approval_routes:
                return (
                    404,
                    {
                        "ok": False,
                        "error_type": "NotFound",
                        "error": f"route not found: {method} {path}",
                    },
                )
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
            if not self.settings.enable_approval_routes:
                return (
                    404,
                    {
                        "ok": False,
                        "error_type": "NotFound",
                        "error": f"route not found: {method} {path}",
                    },
                )
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
