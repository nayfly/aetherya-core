from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ModeThresholds:
    deny_at: int
    confirm_at: int
    log_only_at: int = 0


@dataclass(frozen=True)
class ModeConfig:
    default_state: str
    thresholds: ModeThresholds


@dataclass(frozen=True)
class AggregatorConfig:
    weights: dict[str, float]
    hard_deny_if: list[str]


@dataclass(frozen=True)
class ProceduralGuardConfig:
    critical_tags: list[str]
    privileged_ops: list[str]


@dataclass(frozen=True)
class PolicyConfig:
    version: int
    modes: dict[str, ModeConfig]
    aggregator: AggregatorConfig
    procedural_guard: ProceduralGuardConfig


def _require(d: dict[str, Any], key: str) -> Any:
    if key not in d:
        raise ValueError(f"Missing required key: {key}")
    return d[key]


def load_policy_config(path: str | Path) -> PolicyConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    version = int(_require(data, "version"))

    modes_raw = _require(data, "modes")
    modes: dict[str, ModeConfig] = {}
    for mode_name, m in modes_raw.items():
        thr = _require(m, "thresholds")
        modes[mode_name] = ModeConfig(
            default_state=str(_require(m, "default_state")),
            thresholds=ModeThresholds(
                deny_at=int(_require(thr, "deny_at")),
                confirm_at=int(_require(thr, "confirm_at")),
                log_only_at=int(thr.get("log_only_at", 0)),
            ),
        )

    agg = _require(data, "aggregator")
    aggregator = AggregatorConfig(
        weights=dict(_require(agg, "weights")),
        hard_deny_if=list(_require(agg, "hard_deny_if")),
    )

    pg = _require(data, "procedural_guard")
    procedural_guard = ProceduralGuardConfig(
        critical_tags=list(_require(pg, "critical_tags")),
        privileged_ops=list(_require(pg, "privileged_ops")),
    )

    return PolicyConfig(
        version=version,
        modes=modes,
        aggregator=aggregator,
        procedural_guard=procedural_guard,
    )
