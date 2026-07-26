from __future__ import annotations

import re

from aetherya.actions import ActionRequest

_OPERATIVE_VERBS = re.compile(r"\b(run|execute|delete|send|curl|docker|rm)\b")

# Field extraction. Names are case-insensitive; values keep their original case
# (see parse_user_input for why that matters).
_TOOL_RE = re.compile(r"\btool\s*[:=]\s*([A-Za-z0-9_.:/-]+)", re.IGNORECASE)
_TARGET_RE = re.compile(r"\btarget\s*[:=]\s*(\S+)", re.IGNORECASE)
_PARAM_RE = re.compile(r"\bparam\.([A-Za-z0-9_]+)\s*=\s*(\S+)", re.IGNORECASE)

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

# Meta-questions: the input asks *about* a command rather than asking for it to
# be run. Deliberately narrow — anchored at the start and third-person only, so
# "How do I run a Docker container?" (a request for instructions) is not
# captured while "What does rm -rf do?" is.
_META_QUESTION_FRAMES = re.compile(
    r"^(?:what\s+(?:does|do|is|are)\b"
    r"|how\s+does\b.*\bwork\b"
    r"|explain\b"
    r"|describe\b"
    r"|define\b)"
)

# A clause separator means the input carries more than the meta-question: it may
# chain an actual imperative ("explain and then delete all logs", "explain; rm -rf /").
# Any of these disqualifies the meta frame, so the frame cannot be used as a
# prefix to downgrade a request.
_CLAUSE_SEPARATORS = re.compile(r"[;&|\n]|\band then\b|\bthen\b")


def _is_meta_question(text_lower: str) -> bool:
    if not _META_QUESTION_FRAMES.match(text_lower):
        return False
    return not _CLAUSE_SEPARATORS.search(text_lower)


def parse_user_input(text: str) -> ActionRequest:
    t = (text or "").strip()
    t_lower = t.lower()

    mode_match = re.search(r"\bmode\s*[:=]\s*(consultive|operative)\b", t_lower)
    mode_hint = mode_match.group(1) if mode_match else None

    # Field *names* are matched case-insensitively, but values are read from the
    # original text. Extracting values from the lowercased copy corrupted them:
    # `param.path=/tmp/MyFile.TXT` was recorded and audited as `/tmp/myfile.txt`,
    # which is a different file on any case-sensitive filesystem — the audit
    # trail no longer described the action that was authorised. Tool names stay
    # lowercased on purpose, because the execution allowlist is lowercase.
    tool_match = _TOOL_RE.search(t)
    target_match = _TARGET_RE.search(t)

    params: dict[str, str] = {}
    for m in _PARAM_RE.finditer(t):
        params[m.group(1).lower()] = m.group(2)

    # Operative content signals: explicit tool marker, operative verb keywords, or explicit mode.
    # SECURITY CONTRACT: operative content takes priority over question framing.
    # A text like "Can you run rm -rf /tmp" contains an operative verb and must NOT be
    # downgraded to consultive mode by virtue of starting with "can".
    #
    # NARROW EXCEPTION: a meta-question asks *about* a command rather than for it
    # ("What does rm -rf do?"). Treating a bare mention of a verb as an operation
    # sent every such question to `escalate`. The exception never applies when a
    # tool or operative mode is declared explicitly, and it is not a security
    # boundary on its own: IntentEscalation re-derives operative intent from
    # command shape and from any ProceduralGuard hit, so "explain rm -rf /" is
    # still escalated and denied. See docs/parser-and-input-boundary.md.
    is_meta_question = _is_meta_question(t_lower) and not tool_match and mode_hint != "operative"

    has_operative_content = bool(
        tool_match
        or mode_hint == "operative"
        or (_OPERATIVE_VERBS.search(t_lower) and not is_meta_question)
    )

    if has_operative_content:
        return ActionRequest(
            raw_input=t,
            intent="operate",
            mode_hint=mode_hint or "operative",
            tool=tool_match.group(1).lower() if tool_match else None,
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
        tool=tool_match.group(1).lower() if tool_match else None,
        target=target_match.group(1) if target_match else None,
        parameters=params,
    )
