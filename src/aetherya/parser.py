from __future__ import annotations

import re

from aetherya.actions import ActionRequest


def parse_user_input(text: str) -> ActionRequest:
    t = (text or "").strip()
    t_lower = t.lower()

    mode_match = re.search(r"\bmode\s*[:=]\s*(consultive|operative)\b", t_lower)
    mode_hint = mode_match.group(1) if mode_match else None

    tool_match = re.search(r"\btool\s*[:=]\s*([a-z0-9_.:/-]+)", t_lower)
    target_match = re.search(r"\btarget\s*[:=]\s*([^\s]+)", t_lower)

    params: dict[str, str] = {}
    for m in re.finditer(r"\bparam\.([a-z0-9_]+)\s*=\s*([^\s]+)", t_lower):
        params[m.group(1)] = m.group(2)

    # Questions always resolve to ask/consultive regardless of operative keywords
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
    is_question = t_lower.endswith("?") or any(
        t_lower.startswith(w + " ") or t_lower == w for w in _QUESTION_STARTERS
    )

    if is_question:
        return ActionRequest(
            raw_input=t,
            intent="ask",
            mode_hint=mode_hint or "consultive",
            tool=tool_match.group(1) if tool_match else None,
            target=target_match.group(1) if target_match else None,
            parameters=params,
        )

    # Heurística tonta pero útil (por ahora)
    # Si detectas "run/execute/use tool" -> intent operational
    operative = bool(
        tool_match
        or re.search(r"\b(run|execute|delete|send|curl|docker|rm)\b", t_lower)
        or mode_hint == "operative"
    )

    return ActionRequest(
        raw_input=t,
        intent="operate" if operative else "ask",
        mode_hint=mode_hint or ("operative" if operative else "consultive"),
        tool=tool_match.group(1) if tool_match else None,
        target=target_match.group(1) if target_match else None,
        parameters=params,
    )
