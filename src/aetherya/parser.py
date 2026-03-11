from __future__ import annotations

import re

from aetherya.actions import ActionRequest

_OPERATIVE_VERBS = re.compile(r"\b(run|execute|delete|send|curl|docker|rm)\b")

_QUESTION_STARTERS = (
    "how",
    "what",
    "why",
    "when",
    "where",
    "which",
    "is",
    "are",
    "can",
    "could",
    "would",
    "does",
)


def parse_user_input(text: str) -> ActionRequest:
    t = (text or "").strip()
    t_lower = t.lower()

    mode_match = re.search(r"\bmode\s*[:=]\s*(consultive|operative)\b", t_lower)
    mode_hint = mode_match.group(1) if mode_match else None

    tool_match = re.search(r"\btool\s*[:=]\s*([a-z0-9_.:/-]+)", t_lower)
    target_match = re.search(r"\btarget\s*[:=]\s*([^\s]+)", t_lower)

    # Note: params extracted from t_lower — values are lowercased as a side-effect.
    # Structured callers that need case-preserved values should use ActionRequest directly.
    params: dict[str, str] = {}
    for m in re.finditer(r"\bparam\.([a-z0-9_]+)\s*=\s*([^\s]+)", t_lower):
        params[m.group(1)] = m.group(2)

    # Operative content signals: explicit tool marker, operative verb keywords, or explicit mode.
    # SECURITY CONTRACT: operative content takes priority over question framing.
    # A text like "Can you run rm -rf /tmp" contains an operative verb and must NOT be
    # downgraded to consultive mode by virtue of starting with "can".
    has_operative_content = bool(
        tool_match or _OPERATIVE_VERBS.search(t_lower) or mode_hint == "operative"
    )

    if has_operative_content:
        return ActionRequest(
            raw_input=t,
            intent="operate",
            mode_hint=mode_hint or "operative",
            tool=tool_match.group(1) if tool_match else None,
            target=target_match.group(1) if target_match else None,
            parameters=params,
        )

    # Only reach here when there are NO operative signals.
    # All inputs without operative content are treated as ask/consultive —
    # this is the safe default regardless of whether question framing is detected.
    # The question heuristic is retained as a hint but does not change the security mode.
    return ActionRequest(
        raw_input=t,
        intent="ask",
        mode_hint=mode_hint or "consultive",
        tool=tool_match.group(1) if tool_match else None,
        target=target_match.group(1) if target_match else None,
        parameters=params,
    )
