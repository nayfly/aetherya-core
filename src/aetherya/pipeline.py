from __future__ import annotations

import threading
from typing import Any

from aetherya.actions import Decision, validate_action_request, validate_actor
from aetherya.audit import AuditLogger
from aetherya.capability_gate import CapabilityGate
from aetherya.config import (
    CapabilityMatrixConfig,
    ConfirmationConfig,
    ConfirmationEvidenceConfig,
    ConfirmationRequireConfig,
    ExecutionGateConfig,
    LLMShadowConfig,
    PolicyAdapterShadowConfig,
    PolicyConfig,
)
from aetherya.confirmation_gate import ConfirmationGate, ConfirmationOutcome
from aetherya.constitution import Constitution
from aetherya.execution_gate import ExecutionGate
from aetherya.explainability import ExplainabilityEngine
from aetherya.jailbreak import JailbreakGuard
from aetherya.llm_provider import DryRunLLMProvider, LLMMessage, LLMRequest, OpenAILLMProvider
from aetherya.modes import Mode
from aetherya.parser import parse_user_input
from aetherya.policy_decision_adapter import (
    DryRunPolicyDecisionAdapter,
    PolicyDecisionRequest,
    ensure_policy_decision_adapter,
)
from aetherya.policy_engine import DecisionState, PolicyEngine
from aetherya.procedural_guard import ProceduralGuard
from aetherya.risk import RiskAggregator, RiskDecision, RiskSignal


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 1.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _default_execution_gate_config() -> ExecutionGateConfig:
    return ExecutionGateConfig(
        enabled=True,
        allowed_tools=[],
        require_target_for_operate=False,
        required_parameters={},
        allowed_parameters={},
    )


def _execution_gate_cfg(cfg: PolicyConfig | Any) -> ExecutionGateConfig:
    gate_cfg = getattr(cfg, "execution_gate", None)
    if isinstance(gate_cfg, ExecutionGateConfig):
        return gate_cfg
    return _default_execution_gate_config()


def _default_capability_matrix_config() -> CapabilityMatrixConfig:
    return CapabilityMatrixConfig(
        enabled=False,
        default_allow=False,
        roles={},
        actors={},
    )


def _capability_matrix_cfg(cfg: PolicyConfig | Any) -> CapabilityMatrixConfig:
    capability_cfg = getattr(cfg, "capability_matrix", None)
    if isinstance(capability_cfg, CapabilityMatrixConfig):
        return capability_cfg
    return _default_capability_matrix_config()


def _default_confirmation_config() -> ConfirmationConfig:
    return ConfirmationConfig(
        enabled=False,
        on_confirmed="allow",
        require_for=ConfirmationRequireConfig(
            decisions=["require_confirm"],
            tools=[],
            operations=[],
            min_risk_score=0,
        ),
        evidence=ConfirmationEvidenceConfig(
            token_param="confirm_token",
            context_param="confirm_context",
            token_pattern=r"^ack:[a-z0-9_-]{8,}$",
            min_context_length=12,
        ),
    )


def _confirmation_cfg(cfg: PolicyConfig | Any) -> ConfirmationConfig:
    confirmation_cfg = getattr(cfg, "confirmation", None)
    if isinstance(confirmation_cfg, ConfirmationConfig):
        return confirmation_cfg
    return _default_confirmation_config()


def _policy_fingerprint(cfg: PolicyConfig | Any) -> str | None:
    raw = getattr(cfg, "policy_fingerprint", None)
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    return cleaned if cleaned else None


def _default_llm_shadow_config() -> LLMShadowConfig:
    return LLMShadowConfig(
        enabled=False,
        provider="dry_run",
        model="gpt-dry",
        temperature=0.0,
        max_tokens=128,
        timeout_sec=10.0,
    )


def _llm_shadow_cfg(cfg: PolicyConfig | Any) -> LLMShadowConfig:
    llm_shadow_cfg = getattr(cfg, "llm_shadow", None)
    if isinstance(llm_shadow_cfg, LLMShadowConfig):
        return llm_shadow_cfg
    return _default_llm_shadow_config()


def _build_llm_shadow_provider(shadow_cfg: LLMShadowConfig) -> Any:
    provider = shadow_cfg.provider.strip().lower()
    if provider == "dry_run":
        return DryRunLLMProvider(seed="aetherya-shadow:v1")
    if provider == "openai":
        return OpenAILLMProvider(timeout_sec=shadow_cfg.timeout_sec)
    raise ValueError(f"unsupported llm_shadow.provider: {shadow_cfg.provider}")


def _call_with_timeout(*, callback: Any, timeout_sec: float, timeout_label: str) -> Any:
    if timeout_sec <= 0.0:
        return callback()

    done = threading.Event()
    payload: dict[str, Any] = {}

    def _worker() -> None:
        try:
            payload["response"] = callback()
        except Exception as exc:  # pragma: no cover - surfaced via payload branch
            payload["error"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    done.wait(timeout=float(timeout_sec))
    if not done.is_set():
        raise TimeoutError(f"{timeout_label} timed out after {timeout_sec:.3f}s")

    error = payload.get("error")
    if isinstance(error, Exception):
        raise error

    if "response" not in payload:
        raise RuntimeError(f"{timeout_label} returned no response")

    return payload["response"]


def _default_policy_adapter_shadow_config() -> PolicyAdapterShadowConfig:
    return PolicyAdapterShadowConfig(
        enabled=False,
        max_signals=3,
    )


def _policy_adapter_shadow_cfg(cfg: PolicyConfig | Any) -> PolicyAdapterShadowConfig:
    adapter_cfg = getattr(cfg, "policy_adapter_shadow", None)
    if isinstance(adapter_cfg, PolicyAdapterShadowConfig):
        return adapter_cfg
    return _default_policy_adapter_shadow_config()


def _aggregator_weights(cfg: PolicyConfig | Any) -> dict[str, Any]:
    agg = getattr(cfg, "aggregator", None)
    weights = getattr(agg, "weights", {})
    if isinstance(weights, dict):
        return dict(weights)
    return {}


def _mode_thresholds(cfg: PolicyConfig | Any, mode: str) -> dict[str, int]:
    modes = getattr(cfg, "modes", None)
    if modes is None:
        return {}
    try:
        mode_cfg = modes[mode]
    except Exception:
        return {}

    thresholds = getattr(mode_cfg, "thresholds", None)
    if thresholds is None:
        return {}

    if isinstance(thresholds, dict):
        deny_at = _safe_int(thresholds.get("deny_at", 0), 0)
        confirm_at = _safe_int(thresholds.get("confirm_at", 0), 0)
        log_only_at = _safe_int(thresholds.get("log_only_at", 0), 0)
    else:
        deny_at = _safe_int(getattr(thresholds, "deny_at", 0), 0)
        confirm_at = _safe_int(getattr(thresholds, "confirm_at", 0), 0)
        log_only_at = _safe_int(getattr(thresholds, "log_only_at", 0), 0)

    return {
        "deny_at": deny_at,
        "confirm_at": confirm_at,
        "log_only_at": log_only_at,
    }


def _fail_closed(
    *,
    raw_input: str,
    actor: str,
    mode: Mode,
    stage: str,
    exc: Exception,
    audit: AuditLogger | None,
    policy_fingerprint: str | None = None,
) -> Decision:
    final = Decision(
        allowed=False,
        risk_score=100,
        reason=f"{DecisionState.ESCALATE.value}: fail_closed:{stage} ({type(exc).__name__})",
        violated_principle="FailClosed",
        mode=mode.value,
        state=DecisionState.ESCALATE.value,
    )

    if audit:
        try:
            context: dict[str, Any] = {
                "mode": mode.value,
                "stage": stage,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "signals": [],
            }
            if policy_fingerprint:
                context["policy_fingerprint"] = policy_fingerprint
            audit.log(
                actor=actor,
                action=raw_input,
                decision=final.to_dict(),
                context=context,
            )
        except Exception:
            pass

    return final


def run_pipeline(
    raw_input: str,
    constitution: Constitution,
    actor: str,
    cfg: PolicyConfig,
    audit: AuditLogger | None = None,
) -> Decision:
    # SAFE DEFAULT
    mode: Mode = Mode.CONSULTIVE
    safe_actor = actor if isinstance(actor, str) and actor.strip() else "unknown"
    policy_fingerprint = _policy_fingerprint(cfg)

    if policy_fingerprint:
        audit_targets: list[Any] = []
        if audit:
            audit_targets.append(audit)
        constitution_audit = getattr(constitution, "audit", None)
        if constitution_audit and constitution_audit is not audit:
            audit_targets.append(constitution_audit)

        for target in audit_targets:
            set_fingerprint = getattr(target, "set_policy_fingerprint", None)
            if callable(set_fingerprint):
                try:
                    set_fingerprint(policy_fingerprint)
                except Exception:
                    pass

    # 0) ABI input contract (actor)
    try:
        actor = validate_actor(actor)
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=safe_actor,
            mode=mode,
            stage="actor",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 1) Parse + action request contract + modo (fail-closed si peta)
    try:
        action = parse_user_input(raw_input)
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="parse_user_input",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    try:
        action = validate_action_request(action)
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="action_request",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    try:
        mode = Mode(action.mode_hint) if action.mode_hint else Mode.CONSULTIVE
    except Exception as exc:  # ValueError típico
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="mode",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    signals: list[RiskSignal] = []

    # 2) Execution Gate (fail-closed si peta)
    try:
        gate_result = ExecutionGate(_execution_gate_cfg(cfg)).evaluate(action)
        if gate_result:
            signals.append(
                RiskSignal(
                    source="execution_gate",
                    score=_safe_int(gate_result.get("risk_score", 0), 0),
                    confidence=_safe_float(gate_result.get("confidence", 1.0), 1.0),
                    reason=str(gate_result.get("reason", "")),
                    tags=list(gate_result.get("tags", [])),
                    violated_principle="ExecutionSafety",
                )
            )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="execution_gate",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 3) Capability Gate (fail-closed si peta)
    try:
        capability_result = CapabilityGate(_capability_matrix_cfg(cfg)).evaluate(
            actor=actor, action=action
        )
        if capability_result:
            signals.append(
                RiskSignal(
                    source="capability_gate",
                    score=_safe_int(capability_result.get("risk_score", 0), 0),
                    confidence=_safe_float(capability_result.get("confidence", 1.0), 1.0),
                    reason=str(capability_result.get("reason", "")),
                    tags=list(capability_result.get("tags", [])),
                    violated_principle="CapabilitySafety",
                )
            )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="capability_gate",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 4) Jailbreak Guard (fail-closed si peta)
    try:
        jailbreak_result = JailbreakGuard().evaluate(raw_input)
        if jailbreak_result:
            signals.append(
                RiskSignal(
                    source="jailbreak_guard",
                    score=_safe_int(jailbreak_result.get("risk_score", 0), 0),
                    confidence=_safe_float(jailbreak_result.get("confidence", 1.0), 1.0),
                    reason=str(jailbreak_result.get("reason", "")),
                    tags=list(jailbreak_result.get("tags", [])),
                    violated_principle="PromptSafety",
                )
            )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="jailbreak_guard",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 5) Procedural Guard (fail-closed si peta)
    try:
        guard = ProceduralGuard(cfg.procedural_guard)
        guard_result = guard.evaluate(raw_input)
        if guard_result:
            signals.append(
                RiskSignal(
                    source="procedural_guard",
                    score=_safe_int(guard_result.get("risk_score", 0), 0),
                    confidence=_safe_float(guard_result.get("confidence", 1.0), 1.0),
                    reason=str(guard_result.get("reason", "")),
                    tags=list(guard_result.get("tags", [])),
                    violated_principle="ProceduralSafety",
                )
            )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="procedural_guard",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 6) Constitución (fail-closed si peta)
    try:
        constitution_context: dict[str, Any] = {"mode": mode.value}
        if policy_fingerprint:
            constitution_context["policy_fingerprint"] = policy_fingerprint
        c = constitution.evaluate(action, actor=actor, context=constitution_context)
        signals.append(
            RiskSignal(
                source="constitution",
                score=_safe_int(c.get("risk_score", 0), 0),
                confidence=_safe_float(c.get("confidence", 1.0), 1.0),
                reason=str(c.get("reason", "")),
                tags=list(c.get("tags", [])),
                violated_principle=c.get("violated_principle"),
            )
        )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="constitution",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 7) Agregación final (fail-closed si peta)
    try:
        agg = RiskAggregator(cfg=cfg.aggregator, modes=cfg.modes).aggregate(
            signals, mode=mode.value
        )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="risk_aggregate",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 8) Confirmación fuerte (fail-closed si peta)
    decision_for_engine = agg.decision
    reason_override: str | None = None
    principle_override: str | None = None
    confirmation: ConfirmationOutcome | None = None

    try:
        confirmation = ConfirmationGate(_confirmation_cfg(cfg)).evaluate(
            action=action, aggregate=agg
        )
        if confirmation:
            confirmed = bool(confirmation.get("confirmed", False))
            if not confirmed:
                if agg.decision in {RiskDecision.ALLOW, RiskDecision.LOG_ONLY}:
                    decision_for_engine = RiskDecision.REQUIRE_CONFIRM
                    reason_override = str(
                        confirmation.get("reason", "strong confirmation required")
                    )
                    principle_override = "ConfirmationSafety"
            else:
                override_raw = confirmation.get("override_decision")
                if override_raw and agg.decision == RiskDecision.REQUIRE_CONFIRM:
                    decision_for_engine = RiskDecision(str(override_raw))
                    reason_override = str(
                        confirmation.get("reason", "strong confirmation validated")
                    )
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="confirmation_gate",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    # 9) Mapear a DecisionState (esto ya es determinista)
    engine = PolicyEngine()
    state = engine.evaluate(decision=decision_for_engine, mode=mode)

    final = Decision(
        allowed=(
            state == DecisionState.ALLOW
            or (mode == Mode.CONSULTIVE and state == DecisionState.LOG_ONLY)
        ),
        risk_score=_safe_int(agg.total_score, 0),
        reason=f"{state.value}: "
        + (
            reason_override
            if reason_override
            else (
                agg.top_signal.reason
                if agg.top_signal and agg.top_signal.reason
                else (agg.reasons[0] if agg.reasons else "ok")
            )
        ),
        violated_principle=(
            principle_override
            if principle_override
            else (agg.top_signal.violated_principle if agg.top_signal else None)
        ),
        mode=mode.value,
        state=state.value,
    )
    try:
        final.validate()
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="decision_contract",
            exc=exc,
            audit=audit,
            policy_fingerprint=policy_fingerprint,
        )

    explainability: dict[str, Any] | None = None
    try:
        explainability = ExplainabilityEngine().build(
            signals=agg.breakdown,
            aggregate=agg,
            mode=mode.value,
            weights=_aggregator_weights(cfg),
            thresholds=_mode_thresholds(cfg, mode.value),
            aggregate_decision=agg.decision.value,
            effective_risk_decision=decision_for_engine.value,
            state=state.value,
            allowed=final.allowed,
            reason=final.reason,
            violated_principle=final.violated_principle,
            confirmation=confirmation,
        )
    except Exception:
        explainability = None

    llm_shadow: dict[str, Any] | None = None
    try:
        shadow_cfg = _llm_shadow_cfg(cfg)
        if shadow_cfg.enabled:
            request = LLMRequest(
                model=shadow_cfg.model,
                messages=[
                    LLMMessage(
                        role="system",
                        content=(
                            "Shadow mode only. Analyze decision context and provide dry-run trace."
                        ),
                    ),
                    LLMMessage(role="user", content=raw_input),
                ],
                temperature=shadow_cfg.temperature,
                max_tokens=shadow_cfg.max_tokens,
                metadata={
                    "mode": mode.value,
                    "state": final.state,
                    "decision_reason": final.reason,
                    "policy_fingerprint": policy_fingerprint,
                },
            )

            def _shadow_call() -> Any:
                provider = _build_llm_shadow_provider(shadow_cfg)
                return provider.generate(request)

            response = _call_with_timeout(
                callback=_shadow_call,
                timeout_sec=shadow_cfg.timeout_sec,
                timeout_label="llm_shadow",
            )
            suggested_state_raw = response.metadata.get("suggested_state", final.state)
            suggested_state = (
                suggested_state_raw.strip()
                if isinstance(suggested_state_raw, str) and suggested_state_raw.strip()
                else final.state
            )
            suggested_risk_score = _safe_int(
                response.metadata.get("suggested_risk_score", final.risk_score),
                final.risk_score,
            )
            risk_delta = suggested_risk_score - final.risk_score
            llm_shadow = {
                "enabled": True,
                "provider_configured": shadow_cfg.provider,
                "provider": response.provider,
                "model": response.model,
                "response_id": response.response_id,
                "finish_reason": response.finish_reason,
                "dry_run": response.dry_run,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
                "request_hash": str(response.metadata.get("request_hash", "")),
                "shadow_suggestion": {
                    "text": response.output_text,
                    "suggested_state": suggested_state,
                    "suggested_risk_score": suggested_risk_score,
                },
                "ethical_divergence": {
                    "state_mismatch": suggested_state != final.state,
                    "risk_delta": risk_delta,
                    "absolute_risk_delta": abs(risk_delta),
                },
            }
    except Exception as exc:
        llm_shadow = {
            "enabled": True,
            "provider_configured": _llm_shadow_cfg(cfg).provider,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    policy_adapter_shadow: dict[str, Any] | None = None
    try:
        adapter_cfg = _policy_adapter_shadow_cfg(cfg)
        if adapter_cfg.enabled:
            adapter = ensure_policy_decision_adapter(
                DryRunPolicyDecisionAdapter(seed="aetherya-policy-adapter-shadow:v1")
            )
            trace_id_raw = (
                action.parameters.get("trace_id") if isinstance(action.parameters, dict) else None
            )
            trace_id = (
                trace_id_raw.strip()
                if isinstance(trace_id_raw, str) and trace_id_raw.strip()
                else f"{mode.value}:{actor}"
            )
            adapter_request = PolicyDecisionRequest(
                actor=actor,
                mode=mode.value,
                raw_input=raw_input,
                trace_id=trace_id,
                action={
                    "intent": action.intent,
                    "mode_hint": action.mode_hint,
                    "tool": action.tool,
                    "target": action.target,
                    "parameters": dict(action.parameters),
                },
                baseline={
                    "total_risk": int(agg.total_score),
                    "aggregate_decision": agg.decision.value,
                    "effective_risk_decision": decision_for_engine.value,
                    "state": final.state,
                    "allowed": final.allowed,
                },
                metadata={
                    "policy_fingerprint": policy_fingerprint,
                },
            )
            adapter_response = adapter.suggest(adapter_request)
            adapter_response.validate()

            projected_signals: list[dict[str, Any]] = []
            projected_additional_risk = 0
            for signal in adapter_response.signals[: adapter_cfg.max_signals]:
                signal.validate()
                weighted_score = max(
                    0, _safe_int(round(signal.score * float(signal.confidence)), 0)
                )
                projected_additional_risk += weighted_score
                projected_signals.append(
                    {
                        "source": signal.source,
                        "score": signal.score,
                        "confidence": signal.confidence,
                        "reason": signal.reason,
                        "tags": list(signal.tags),
                        "violated_principle": signal.violated_principle,
                        "weighted_score": weighted_score,
                    }
                )

            policy_adapter_shadow = {
                "enabled": True,
                "adapter": adapter_response.adapter,
                "request_id": adapter_response.request_id,
                "dry_run": adapter_response.dry_run,
                "max_signals": adapter_cfg.max_signals,
                "signals": projected_signals,
                "projected_additional_risk": projected_additional_risk,
                "projected_total_risk": _safe_int(agg.total_score, 0) + projected_additional_risk,
                "request_hash": str(adapter_response.metadata.get("request_hash", "")),
                "decision_candidates": [
                    {
                        "state": candidate.state,
                        "confidence": candidate.confidence,
                        "reason": candidate.reason,
                    }
                    for candidate in adapter_response.decision_candidates
                ],
            }
    except Exception as exc:
        policy_adapter_shadow = {
            "enabled": True,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    if audit:
        try:
            context: dict[str, Any] = {
                "mode": mode.value,
                "signals": [s.__dict__ for s in agg.breakdown],
            }
            if explainability:
                context["explainability"] = explainability
            if llm_shadow:
                context["llm_shadow"] = llm_shadow
            if policy_adapter_shadow:
                context["policy_adapter_shadow"] = policy_adapter_shadow
            if policy_fingerprint:
                context["policy_fingerprint"] = policy_fingerprint
            audit.log(
                actor=actor,
                action=raw_input,
                decision=final.to_dict(),
                context=context,
            )
        except Exception:
            pass

    return final
