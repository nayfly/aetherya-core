from __future__ import annotations

import re
from dataclasses import dataclass, replace

from aetherya.actions import ActionRequest
from aetherya.config import IntentEscalationConfig, ProceduralGuardConfig
from aetherya.procedural_guard import ProceduralGuard
from aetherya.text_normalize import normalize_security_text


@dataclass(frozen=True)
class IntentEscalationOutcome:
    escalated: bool
    from_intent: str
    to_intent: str
    from_mode: str | None
    to_mode: str | None
    tags: list[str]
    reason: str


# Binaries whose presence alongside a flag or an absolute path means the input
# carries an actual command, not a discussion of one. Deliberately narrower than
# "any verb" — the shape requirement is what keeps false positives down.
_EXECUTABLE_BINARIES = (
    "apt|apt-get|aws|az|blkid|chattr|chgrp|chmod|chown|crontab|dd|dnf|docker|fdisk|"
    "gcloud|git|iptables|journalctl|kill|killall|kubectl|mkfs|mount|mv|npm|nc|parted|"
    "passwd|pip|pkill|poweroff|reboot|rsync|scp|sed|shred|shutdown|ssh|systemctl|"
    "tar|terraform|umount|useradd|userdel|usermod|wipefs|yum"
)

_SHAPE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        # Command substitution: $(...) or `...`
        re.compile(r"\$\([^)]*\)|`[^`]+`"),
        "command_substitution",
    ),
    (
        # Anything piped into a shell interpreter.
        re.compile(r"\|\s*(?:sudo\s+)?[a-z]{0,3}sh\b"),
        "pipe_to_shell",
    ),
    (
        # Redirect into an absolute path or device.
        re.compile(r">>?\s*/\S+"),
        "redirect_to_path",
    ),
    (
        # A known binary followed by a flag or an absolute path.
        re.compile(rf"\b(?:{_EXECUTABLE_BINARIES})\s+(?:-{{1,2}}[a-z0-9]|/\S)"),
        "binary_with_arguments",
    ),
    (
        # dd-style key=value operands (if=/dev/zero of=/dev/sda).
        re.compile(r"\b(?:if|of)\s*=\s*/dev/\S+"),
        "device_operand",
    ),
    (
        # Privilege escalation prefixing another command.
        re.compile(r"\bsudo\s+[a-z][a-z0-9._-]*\b"),
        "privilege_escalation",
    ),
)


class IntentEscalator:
    """
    Raises an ActionRequest to `operate`/`operative` when the raw input carries
    executable command shape, independent of how the parser classified it.

    Why this exists
    ---------------
    ExecutionGate and the capability matrix only evaluate requests whose intent
    is `operate`. That made every downstream gate depend on the parser's verb
    list: an executable command using a verb the parser did not know (e.g.
    `dd if=/dev/zero of=/dev/sda`) was classified `ask`, skipped the gates
    entirely, and could reach `allow`. This stage removes that coupling.

    The escalation is strictly monotone — it only ever moves toward the
    stricter classification, never away from it — so it cannot be used to
    downgrade a request that the parser already flagged as operative.
    """

    def __init__(
        self,
        cfg: IntentEscalationConfig,
        procedural_cfg: ProceduralGuardConfig | None = None,
    ) -> None:
        self.cfg = cfg
        self._procedural_guard = ProceduralGuard(procedural_cfg) if procedural_cfg else None

    def _detect(self, raw_input: str) -> list[str]:
        normalized = normalize_security_text(raw_input)
        if not normalized:
            return []

        tags: list[str] = []

        # A procedural hit means the text contains a real destructive command;
        # that is the strongest possible evidence of operative content.
        if self.cfg.use_procedural_signal and self._procedural_guard is not None:
            if self._procedural_guard.evaluate(raw_input) is not None:
                tags.append("procedural_command_detected")

        if self.cfg.use_shape_signals:
            for pattern, tag in _SHAPE_RULES:
                if pattern.search(normalized) and tag not in tags:
                    tags.append(tag)

        return tags

    def evaluate(self, action: ActionRequest, raw_input: str) -> IntentEscalationOutcome:
        from_intent = action.intent
        from_mode = action.mode_hint

        if not self.cfg.enabled or from_intent == "operate":
            return IntentEscalationOutcome(
                escalated=False,
                from_intent=from_intent,
                to_intent=from_intent,
                from_mode=from_mode,
                to_mode=from_mode,
                tags=[],
                reason="",
            )

        tags = self._detect(raw_input)
        if not tags:
            return IntentEscalationOutcome(
                escalated=False,
                from_intent=from_intent,
                to_intent=from_intent,
                from_mode=from_mode,
                to_mode=from_mode,
                tags=[],
                reason="",
            )

        return IntentEscalationOutcome(
            escalated=True,
            from_intent=from_intent,
            to_intent="operate",
            from_mode=from_mode,
            to_mode="operative",
            tags=tags,
            reason="executable command shape detected in non-operative request",
        )


def apply_escalation(action: ActionRequest, outcome: IntentEscalationOutcome) -> ActionRequest:
    """Return the escalated ActionRequest, or the original when no escalation applies."""
    if not outcome.escalated:
        return action
    return replace(action, intent=outcome.to_intent, mode_hint=outcome.to_mode)
