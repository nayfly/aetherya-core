from __future__ import annotations

from typing import Any

from aetherya.actions import Decision
from aetherya.audit import AuditLogger
from aetherya.config import PolicyConfig
from aetherya.constitution import Constitution
from aetherya.modes import Mode
from aetherya.parser import parse_user_input
from aetherya.policy_engine import DecisionState
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
    )

    if audit:
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

    # 1) Parse + modo (fail-closed si peta)
    try:
        action = parse_user_input(raw_input)
        if action.mode_hint:
            try:
                mode = Mode(action.mode_hint)
            except ValueError:
                # modo inválido => default seguro
                mode = Mode.CONSULTIVE
        else:
            mode = Mode.CONSULTIVE
    except Exception as exc:
        return _fail_closed(
            raw_input=raw_input,
            actor=actor,
            mode=mode,
            stage="parse_user_input",
            exc=exc,
            audit=audit,
        )

    signals: list[RiskSignal] = []

    # 2) Procedural Guard (fail-closed si peta)
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

    # 3) Constitución (fail-closed si peta)
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

    # 4) Agregación final (fail-closed si peta)
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

    # 5) Mapear a DecisionState (esto ya es determinista)
    if agg.decision == RiskDecision.DENY:
        state = DecisionState.DENY
    elif agg.decision == RiskDecision.REQUIRE_CONFIRM:
        state = DecisionState.ESCALATE
    elif agg.decision == RiskDecision.LOG_ONLY:
        state = DecisionState.LOG_ONLY
    else:
        state = DecisionState.ALLOW

    final = Decision(
        allowed=(state == DecisionState.ALLOW),
        risk_score=_safe_int(agg.total_score, 0),
        reason=f"{state.value}: " + (agg.reasons[0] if agg.reasons else "ok"),
        violated_principle=(agg.top_signal.violated_principle if agg.top_signal else None),
        mode=mode.value,
    )

    if audit:
        audit.log(
            actor=actor,
            action=raw_input,
            decision=final.to_dict(),
            context={
                "mode": mode.value,
                "signals": [s.__dict__ for s in agg.breakdown],
            },
        )

    return final
