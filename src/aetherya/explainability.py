from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aetherya.risk import RiskAggregate, RiskSignal


class ExplainabilityEngine:
    def _weight_for_source(self, weights: dict[str, Any], source: str) -> float:
        raw = weights.get(source, 1.0)
        try:
            weight = float(raw)
        except (TypeError, ValueError):
            return 1.0
        return max(0.0, weight)

    def _contributors(
        self,
        *,
        signals: list[RiskSignal],
        weights: dict[str, Any],
        total_score: int,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for idx, signal in enumerate(signals):
            weight = self._weight_for_source(weights, signal.source)
            weighted_score = int(round(signal.score * signal.confidence * weight))
            contribution_ratio = (weighted_score / total_score) if total_score > 0 else 0.0
            items.append(
                {
                    "id": f"signal:{idx}",
                    "source": signal.source,
                    "raw_score": int(signal.score),
                    "confidence": float(signal.confidence),
                    "weight": float(weight),
                    "weighted_score": int(weighted_score),
                    "contribution_ratio": float(contribution_ratio),
                    "reason": signal.reason,
                    "tags": list(signal.tags),
                    "violated_principle": signal.violated_principle,
                }
            )

        items.sort(key=lambda item: (-item["weighted_score"], str(item["source"])))
        return items

    def build(
        self,
        *,
        signals: list[RiskSignal],
        aggregate: RiskAggregate,
        mode: str,
        weights: dict[str, Any] | None,
        thresholds: dict[str, int] | None,
        aggregate_decision: str,
        effective_risk_decision: str,
        state: str,
        allowed: bool,
        reason: str,
        violated_principle: str | None,
        confirmation: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        safe_weights = dict(weights or {})
        safe_thresholds = dict(thresholds or {})

        contributors = self._contributors(
            signals=signals,
            weights=safe_weights,
            total_score=int(aggregate.total_score),
        )

        nodes: list[dict[str, Any]] = [
            {
                "id": "aggregate",
                "type": "aggregate",
                "label": "RiskAggregate",
                "data": {
                    "mode": mode,
                    "total_score": int(aggregate.total_score),
                    "decision": aggregate_decision,
                    "thresholds": safe_thresholds,
                },
            },
            {
                "id": "risk_decision",
                "type": "risk_decision",
                "label": "RiskDecision",
                "data": {
                    "aggregate_decision": aggregate_decision,
                    "effective_risk_decision": effective_risk_decision,
                },
            },
            {
                "id": "decision_state",
                "type": "decision_state",
                "label": "PolicyDecision",
                "data": {
                    "state": state,
                    "allowed": bool(allowed),
                    "reason": reason,
                    "violated_principle": violated_principle,
                },
            },
        ]

        edges: list[dict[str, Any]] = []
        for contributor in contributors:
            node_id = str(contributor["id"])
            nodes.append(
                {
                    "id": node_id,
                    "type": "signal",
                    "label": str(contributor["source"]),
                    "data": contributor,
                }
            )
            edges.append(
                {
                    "from": node_id,
                    "to": "aggregate",
                    "type": "contributes_to",
                    "data": {
                        "weighted_score": contributor["weighted_score"],
                        "weight": contributor["weight"],
                        "contribution_ratio": contributor["contribution_ratio"],
                    },
                }
            )

        edges.append(
            {
                "from": "aggregate",
                "to": "risk_decision",
                "type": "aggregated_to",
                "data": {"decision": aggregate_decision},
            }
        )

        if confirmation:
            nodes.append(
                {
                    "id": "confirmation_gate",
                    "type": "confirmation_gate",
                    "label": "ConfirmationGate",
                    "data": {
                        "required": bool(confirmation.get("required", False)),
                        "confirmed": bool(confirmation.get("confirmed", False)),
                        "reason": str(confirmation.get("reason", "")),
                        "tags": list(confirmation.get("tags", [])),
                        "override_decision": confirmation.get("override_decision"),
                    },
                }
            )
            edges.append(
                {
                    "from": "risk_decision",
                    "to": "confirmation_gate",
                    "type": "checked_by_confirmation",
                    "data": {"decision": aggregate_decision},
                }
            )
            edges.append(
                {
                    "from": "confirmation_gate",
                    "to": "decision_state",
                    "type": "resolved_to_state",
                    "data": {"effective_risk_decision": effective_risk_decision, "state": state},
                }
            )
        else:
            edges.append(
                {
                    "from": "risk_decision",
                    "to": "decision_state",
                    "type": "resolved_to_state",
                    "data": {"effective_risk_decision": effective_risk_decision, "state": state},
                }
            )

        return {
            "version": "v1",
            "summary": {
                "mode": mode,
                "risk_score": int(aggregate.total_score),
                "aggregate_decision": aggregate_decision,
                "effective_risk_decision": effective_risk_decision,
                "state": state,
                "allowed": bool(allowed),
                "reason": reason,
                "violated_principle": violated_principle,
                "top_contributor": contributors[0]["source"] if contributors else None,
            },
            "contributors": contributors,
            "graph": {
                "nodes": nodes,
                "edges": edges,
            },
        }
