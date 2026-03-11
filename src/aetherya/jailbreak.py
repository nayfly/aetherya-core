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
        # Paraphrase: "set aside / overlook / discard ... instructions/rules/guidelines"
        (
            re.compile(
                r"\b(set aside|overlook|discard)\b.{0,50}"
                r"\b(instructions|rules|guidelines|safety|constraints)\b"
            ),
            "ignore_instructions_paraphrase",
        ),
        # Paraphrase: "pay no attention to ... rules/instructions"
        (
            re.compile(
                r"\bpay no attention to\b.{0,50}" r"\b(instructions|rules|guidelines|safety)\b"
            ),
            "ignore_instructions_paraphrase",
        ),
        # Paraphrase: "pretend ... no rules" / "forget ... guidelines"
        (
            re.compile(r"\bpretend\b.{0,50}\bno rules\b"),
            "ignore_instructions_paraphrase",
        ),
        (
            re.compile(r"\bforget\b.{0,50}\bguidelines\b"),
            "ignore_instructions_paraphrase",
        ),
        # Role override paraphrases
        (
            re.compile(r"\bpretend you are\b"),
            "role_override_paraphrase",
        ),
        (
            re.compile(r"\bact as if you were\b"),
            "role_override_paraphrase",
        ),
        (
            re.compile(r"\bsimulate being\b"),
            "role_override_paraphrase",
        ),
        (
            re.compile(r"\broleplay as\b.{0,40}\bunrestricted\b"),
            "role_override_paraphrase",
        ),
        (
            re.compile(r"\byou are now\b"),
            "role_override_paraphrase",
        ),
        # Policy override paraphrases
        (
            re.compile(
                r"\brespond without\b.{0,50}"
                r"\b(restrictions|filters|guidelines|safety|limitations)\b"
            ),
            "policy_override_paraphrase",
        ),
        (
            re.compile(r"\banswer freely\b"),
            "policy_override_paraphrase",
        ),
        (
            re.compile(r"\bno limitations\b"),
            "policy_override_paraphrase",
        ),
        (
            re.compile(r"\b(uncensored|unrestricted) mode\b"),
            "policy_override_paraphrase",
        ),
        # Exfiltration paraphrases
        (
            re.compile(r"\brepeat your instructions\b"),
            "prompt_exfiltration_paraphrase",
        ),
        (
            re.compile(r"\bwhat were you told\b"),
            "prompt_exfiltration_paraphrase",
        ),
        (
            re.compile(r"\bshow me your prompt\b"),
            "prompt_exfiltration_paraphrase",
        ),
        (
            re.compile(r"\bdisplay your system\b"),
            "prompt_exfiltration_paraphrase",
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
