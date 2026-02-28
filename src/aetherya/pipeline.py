from __future__ import annotations

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
    PolicyConfig,
)
from aetherya.confirmation_gate import ConfirmationGate
from aetherya.constitution import Constitution
from aetherya.execution_gate import ExecutionGate
from aetherya.jailbreak import JailbreakGuard
from aetherya.modes import Mode
from aetherya.parser import parse_user_input
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


def _fail_closed(
    *,
    raw_input: str,
    actor: str,
    mode: Mode,
    stage: str,
    exc: Exception,
    audit: AuditLogger | None,
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
            audit.log(
                actor=actor,
                action=raw_input,
                decision=final.to_dict(),
                context={
                    "mode": mode.value,
                    "stage": stage,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "signals": [],
                },
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
        )

    # 6) Constitución (fail-closed si peta)
    try:
        c = constitution.evaluate(action, actor=actor, context={"mode": mode.value})
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
        )

    # 8) Confirmación fuerte (fail-closed si peta)
    decision_for_engine = agg.decision
    reason_override: str | None = None
    principle_override: str | None = None

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
        )

    if audit:
        try:
            audit.log(
                actor=actor,
                action=raw_input,
                decision=final.to_dict(),
                context={
                    "mode": mode.value,
                    "signals": [s.__dict__ for s in agg.breakdown],
                },
            )
        except Exception:
            pass

    return final
