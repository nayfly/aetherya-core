from __future__ import annotations

import re
from typing import TypedDict


class JailbreakResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


class JailbreakGuard:
    _PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (
            re.compile(
                r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior)\s+"
                r"(instructions|rules|system prompt|safety)\b"
            ),
            "ignore_previous_instructions",
        ),
        (
            re.compile(
                r"\b(system prompt|developer message)\b.*\b(reveal|show|print|leak|output)\b|\b"
                r"(reveal|show|print|leak|output)\b.*\b(system prompt|developer message)\b"
            ),
            "prompt_exfiltration",
        ),
        (
            re.compile(
                r"\b(bypass|disable|remove)\b.*\b(safety|guardrails|filters|restrictions)\b|\b"
                r"(safety|guardrails|filters|restrictions)\b.*\b(bypass|disable|remove)\b"
            ),
            "safety_bypass",
        ),
        (
            re.compile(r"\b(dan mode|developer mode|jailbreak mode|act as unrestricted)\b"),
            "role_override",
        ),
        (
            re.compile(r"\b(do anything now|no rules|without restrictions|unfiltered)\b"),
            "policy_override",
        ),
    )

    def evaluate(self, text: str) -> JailbreakResult | None:
        t = (text or "").strip().lower()
        if not t:
            return None

        for pattern, tag in self._PATTERNS:
            if pattern.search(t):
                return {
                    "risk_score": 95,
                    "confidence": 0.95,
                    "reason": "prompt injection attempt",
                    "tags": ["jailbreak_attempt", "prompt_injection", tag],
                }

        return None
