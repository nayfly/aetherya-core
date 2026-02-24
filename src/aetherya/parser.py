from __future__ import annotations

import re

from aetherya.actions import ActionRequest


def parse_user_input(text: str) -> ActionRequest:
    t = (text or "").strip()

    # Heurística tonta pero útil (por ahora)
    # Si detectas “run/execute/use tool” -> intent operational
    operative = bool(re.search(r"\b(run|execute|delete|send|curl|docker|rm)\b", t.lower()))

    return ActionRequest(
        raw_input=t,
        intent="operate" if operative else "ask",
        mode_hint="operative" if operative else "consultive",
        tool=None,
        target=None,
        parameters={},
    )
