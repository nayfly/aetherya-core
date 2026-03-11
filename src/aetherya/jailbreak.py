from __future__ import annotations

import re
import unicodedata
from typing import TypedDict


class JailbreakResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


def _normalize_jailbreak_text(text: str) -> str:
    """
    Normalize text for jailbreak detection.

    Pipeline: lowercase → NFKD decomposition → strip combining characters and
    Unicode format characters → compact whitespace.

    This eliminates:
    - Zero-width chars (U+200B/C/D, U+FEFF, etc.) — Unicode category 'Cf'
    - Diacritic variants (ïgnore → ignore, Einschränkungen → einschrankungen)
    - Fullwidth char decompositions via NFKD

    It does NOT handle ASCII l33tspeak (1gn0r3) — that substitution step
    carries meaningful false-positive risk for legitimate inputs.
    """
    lowered = text.lower()
    folded = unicodedata.normalize("NFKD", lowered)
    # Strip combining diacritics AND Unicode format/invisible characters (category Cf).
    # Category Cf covers: zero-width space (U+200B), zero-width non-joiner (U+200C),
    # zero-width joiner (U+200D), BOM (U+FEFF), soft hyphen (U+00AD), etc.
    ascii_only = "".join(
        ch for ch in folded if not unicodedata.combining(ch) and unicodedata.category(ch) != "Cf"
    )
    compact = re.sub(r"\s+", " ", ascii_only).strip()
    return compact


class JailbreakGuard:
    # Each entry: (compiled pattern, tag).
    # Patterns are written in post-normalization form (ASCII, no diacritics).
    # All patterns are evaluated; all matching tags are collected for telemetry.
    _PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        # ── English: core patterns ──────────────────────────────────────────────
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
        # ── English: paraphrase patterns ────────────────────────────────────────
        (
            re.compile(
                r"\b(set aside|overlook|discard)\b.{0,50}"
                r"\b(instructions|rules|guidelines|safety|constraints)\b"
            ),
            "ignore_instructions_paraphrase",
        ),
        (
            re.compile(
                r"\bpay no attention to\b.{0,50}" r"\b(instructions|rules|guidelines|safety)\b"
            ),
            "ignore_instructions_paraphrase",
        ),
        (
            re.compile(r"\bpretend\b.{0,50}\bno rules\b"),
            "ignore_instructions_paraphrase",
        ),
        (
            re.compile(r"\bforget\b.{0,50}\bguidelines\b"),
            "ignore_instructions_paraphrase",
        ),
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
        # ── Spanish ─────────────────────────────────────────────────────────────
        # After NFKD normalization: "instrucciones" stays, "instrucción" → "instruccion"
        (
            re.compile(
                r"\bignora\b.{0,50}\b(instrucciones|reglas|normas|restricciones|directrices)\b"
            ),
            "ignore_instructions_es",
        ),
        (
            re.compile(r"\bolvida\b.{0,50}\b(instrucciones|reglas|directrices|normas|pautas)\b"),
            "ignore_instructions_es",
        ),
        (
            re.compile(r"\bactua como si fueras\b"),
            "role_override_es",
        ),
        (
            re.compile(r"\bfinge que eres\b"),
            "role_override_es",
        ),
        (
            re.compile(r"\beres ahora\b"),
            "role_override_es",
        ),
        (
            re.compile(r"\bresponde sin\b.{0,50}\b(restricciones|filtros|limitaciones|censura)\b"),
            "policy_override_es",
        ),
        (
            re.compile(r"\bmodo (sin censura|sin restricciones|sin filtros|no censurado)\b"),
            "policy_override_es",
        ),
        (
            re.compile(r"\bmuestrame (tu )?(prompt|instrucciones|sistema)\b"),
            "prompt_exfiltration_es",
        ),
        (
            re.compile(r"\brepite (tus )?(instrucciones|ordenes)\b"),
            "prompt_exfiltration_es",
        ),
        # ── French ──────────────────────────────────────────────────────────────
        # After NFKD: "précédentes" → "precedentes", "règles" → "regles"
        (
            re.compile(r"\bignore les\b.{0,50}\b(instructions|regles|directives|contraintes)\b"),
            "ignore_instructions_fr",
        ),
        (
            re.compile(r"\boublie les\b.{0,50}\b(instructions|regles|directives|consignes)\b"),
            "ignore_instructions_fr",
        ),
        (
            re.compile(r"\bagis comme si tu etais\b"),
            "role_override_fr",
        ),
        (
            re.compile(r"\bfais semblant d.{0,2}etre\b"),
            "role_override_fr",
        ),
        (
            re.compile(r"\btu es maintenant\b"),
            "role_override_fr",
        ),
        (
            re.compile(r"\breponds sans\b.{0,50}\b(restrictions?|filtres?|limitations?|censure)\b"),
            "policy_override_fr",
        ),
        (
            re.compile(r"\bmode (non censure|sans restrictions?|non filtre)\b"),
            "policy_override_fr",
        ),
        (
            re.compile(r"\bmontre.{0,5}moi (ton )?(prompt|instructions|systeme)\b"),
            "prompt_exfiltration_fr",
        ),
        (
            re.compile(r"\brepete (tes )?(instructions|ordres)\b"),
            "prompt_exfiltration_fr",
        ),
        # ── German ──────────────────────────────────────────────────────────────
        # After NFKD: "ä"→"a", "ö"→"o", "ü"→"u", "ß"→"ss" (NFKD doesn't decompose ß,
        # but "Einschränkungen"→"einschrankungen" because ä decomposes to a+combining)
        (
            re.compile(r"\bignoriere\b.{0,50}\b(anweisungen|regeln|richtlinien|vorgaben)\b"),
            "ignore_instructions_de",
        ),
        (
            re.compile(r"\bvergiss\b.{0,50}\b(anweisungen|regeln|richtlinien|vorgaben)\b"),
            "ignore_instructions_de",
        ),
        (
            re.compile(r"\btu so als (warst|ob) du\b"),
            "role_override_de",
        ),
        (
            re.compile(r"\bdu bist jetzt\b"),
            "role_override_de",
        ),
        (
            re.compile(r"\bab jetzt bist du\b"),
            "role_override_de",
        ),
        (
            re.compile(r"\bohne (einschrankungen|filter|beschrankungen|zensur|einschrankung)\b"),
            "policy_override_de",
        ),
        (
            re.compile(r"\bzeig mir (deinen? )?(prompt|anweisungen|system)\b"),
            "prompt_exfiltration_de",
        ),
        (
            re.compile(r"\bwiederhole (deine )?(anweisungen|instruktionen)\b"),
            "prompt_exfiltration_de",
        ),
        (
            re.compile(r"\bunzensiert\w* (modus|ai|assistent)\b"),
            "policy_override_de",
        ),
    )

    def evaluate(self, text: str) -> JailbreakResult | None:
        t = _normalize_jailbreak_text(text)
        if not t:
            return None

        # Collect all matching tags for complete telemetry.
        matched_tags: list[str] = []
        for pattern, tag in self._PATTERNS:
            if pattern.search(t):
                if tag not in matched_tags:
                    matched_tags.append(tag)

        if not matched_tags:
            return None

        return {
            "risk_score": 95,
            "confidence": 0.95,
            "reason": "prompt injection attempt",
            "tags": ["jailbreak_attempt", "prompt_injection", *matched_tags],
        }
