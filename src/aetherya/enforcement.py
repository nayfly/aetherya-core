from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from aetherya.actions import Decision

# ---------------------------------------------------------------------------
# Rollout phases as configuration.
#
# The engine always computes a full decision. A phase only decides how much of
# it is enforced. Keeping that split here — rather than in each integration —
# is what makes "deploy in observation mode, tighten later" a config change
# instead of a code change, and what makes the shadow gap measurable: in phase 1
# we still know what a later phase *would* have refused.
#
# See docs/rollout-phases.md.
# ---------------------------------------------------------------------------

# States a later phase would act on, ordered from most to least severe.
_ENFORCEABLE: Final[frozenset[str]] = frozenset({"hard_deny", "deny", "escalate"})


@dataclass(frozen=True)
class EnforcementPhase:
    number: int
    name: str
    blocks: frozenset[str]
    confirms: frozenset[str]
    description: str


PHASES: Final[dict[int, EnforcementPhase]] = {
    1: EnforcementPhase(
        number=1,
        name="shadow",
        blocks=frozenset(),
        confirms=frozenset(),
        description="observe only — every action executes, every decision is recorded",
    ),
    2: EnforcementPhase(
        number=2,
        name="hard_deny",
        blocks=frozenset({"hard_deny"}),
        confirms=frozenset(),
        description="refuse irreversible destruction, jailbreaks and unlisted tools",
    ),
    3: EnforcementPhase(
        number=3,
        name="full",
        blocks=frozenset({"hard_deny", "deny"}),
        confirms=frozenset({"escalate"}),
        description="refuse denials and hold escalations for human confirmation",
    ),
}

MIN_PHASE: Final[int] = min(PHASES)
MAX_PHASE: Final[int] = max(PHASES)


def resolve_phase(number: int) -> EnforcementPhase:
    if number not in PHASES:
        raise ValueError(f"enforcement.phase must be one of {sorted(PHASES)}, got {number!r}")
    return PHASES[number]


@dataclass(frozen=True)
class Enforcement:
    """What the caller should actually do with a decision, under a given phase."""

    phase: int
    state: str
    execute: bool
    requires_confirmation: bool
    reason: str
    # True when this executed but a later phase would have refused it. This is
    # the number phase 1 exists to produce; it is meaningless once phase 3 is on.
    shadow_gap: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "state": self.state,
            "execute": self.execute,
            "requires_confirmation": self.requires_confirmation,
            "reason": self.reason,
            "shadow_gap": self.shadow_gap,
        }


def apply_enforcement(decision: Decision, phase: EnforcementPhase | int) -> Enforcement:
    """
    Map a decision to an action under the configured phase.

    Never mutates the decision: the audit trail records what the engine ruled,
    not what a partially-enforcing deployment chose to do about it. The two are
    different facts and conflating them would make phase 1 data worthless.
    """
    resolved = phase if isinstance(phase, EnforcementPhase) else resolve_phase(phase)
    state = decision.state

    if state in resolved.blocks:
        return Enforcement(
            phase=resolved.number,
            state=state,
            execute=False,
            requires_confirmation=False,
            reason=f"refused: `{state}` is enforced in phase {resolved.number}",
            shadow_gap=False,
        )

    if state in resolved.confirms:
        return Enforcement(
            phase=resolved.number,
            state=state,
            execute=False,
            requires_confirmation=True,
            reason=f"held: `{state}` requires human confirmation in phase {resolved.number}",
            shadow_gap=False,
        )

    gap = state in _ENFORCEABLE
    return Enforcement(
        phase=resolved.number,
        state=state,
        execute=True,
        requires_confirmation=False,
        reason=(
            f"executed: phase {resolved.number} does not enforce `{state}`"
            if gap
            else "allowed by policy"
        ),
        shadow_gap=gap,
    )
