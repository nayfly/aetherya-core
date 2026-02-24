from __future__ import annotations

from aetherya.actions import Decision
from aetherya.audit import AuditLogger
from aetherya.config import PolicyConfig
from aetherya.constitution import Constitution
from aetherya.modes import Mode
from aetherya.parser import parse_user_input
from aetherya.policy_engine import DecisionState
from aetherya.procedural_guard import ProceduralGuard
from aetherya.risk import RiskAggregator, RiskDecision, RiskSignal


def run_pipeline(
    raw_input: str,
    constitution: Constitution,
    actor: str,
    cfg: PolicyConfig,
    audit: AuditLogger | None = None,
) -> Decision:
    action = parse_user_input(raw_input)
    mode = Mode(action.mode_hint) if action.mode_hint else Mode.CONSULTIVE

    signals: list[RiskSignal] = []

    guard = ProceduralGuard(cfg.procedural_guard)
    guard_result = guard.evaluate(raw_input)
    if guard_result:
        signals.append(
            RiskSignal(
                source="procedural_guard",
                score=int(guard_result.get("risk_score", 0)),
                confidence=float(guard_result.get("confidence", 1.0)),
                reason=str(guard_result.get("reason", "")),
                tags=list(guard_result.get("tags", [])),
                violated_principle="ProceduralSafety",
            )
        )

    # 2) Constitución (señal)
    c = constitution.evaluate(action, actor=actor, context={"mode": mode.value})
    signals.append(
        RiskSignal(
            source="constitution",
            score=int(c.get("risk_score", 0)),
            confidence=float(c.get("confidence", 1.0)) if "confidence" in c else 1.0,
            reason=str(c.get("reason", "")),
            tags=list(c.get("tags", [])),
            violated_principle=c.get("violated_principle"),
        )
    )

    # 3) Agregación final
    agg = RiskAggregator(cfg=cfg.aggregator, modes=cfg.modes).aggregate(signals, mode=mode.value)

    # 4) Mapear a DecisionState
    if agg.decision == RiskDecision.DENY:
        state = DecisionState.DENY
    elif agg.decision == RiskDecision.REQUIRE_CONFIRM:
        state = DecisionState.ESCALATE  # mejor que LOG_ONLY si existe
    elif agg.decision == RiskDecision.LOG_ONLY:
        state = DecisionState.LOG_ONLY
    else:
        state = DecisionState.ALLOW

    # 5) Decision final (snapshot-friendly)
    final = Decision(
        allowed=(state == DecisionState.ALLOW),
        risk_score=int(agg.total_score),
        reason=f"{state.value}: " + (agg.reasons[0] if agg.reasons else "ok"),
        violated_principle=(agg.top_signal.violated_principle if agg.top_signal else None),
        mode=mode.value,
    )

    # 6) Audit
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
