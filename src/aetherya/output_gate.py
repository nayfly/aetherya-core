from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Final


def _normalize_text(value: str) -> str:
    lowered = value.lower()
    folded = unicodedata.normalize("NFKD", lowered)
    ascii_only = "".join(ch for ch in folded if not unicodedata.combining(ch))
    compact = re.sub(r"\s+", " ", ascii_only).strip()
    return compact


def _compile_term_pattern(term: str) -> re.Pattern[str]:
    # Left/right boundaries avoid matching term fragments inside larger tokens.
    return re.compile(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])")


@dataclass(frozen=True)
class OutputGateVerdict:
    blocked: bool
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]
    violated_principle: str
    matched_terms: list[str]


_PII_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Email
    (
        re.compile(r"\b[\w.+\-]+@[\w\-]+\.[\w.\-]+\b"),
        "email",
    ),
    # Credit card: 13-16 digits, optional space/dash separators between groups
    (
        re.compile(r"\b(?:\d{4}[ -]?){3}\d{1,4}\b"),
        "credit_card",
    ),
    # API keys: OpenAI sk-, GitHub ghp_, Slack xox*, generic Bearer
    (
        re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
        "api_key",
    ),
    (
        re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
        "api_key",
    ),
    (
        re.compile(r"\bxox[baprs]-[a-zA-Z0-9\-]+\b"),
        "api_key",
    ),
    (
        re.compile(r"\bBearer\s+[a-zA-Z0-9._\-]{10,}\b"),
        "api_key",
    ),
    # DNI español: 8 digits + letter
    (
        re.compile(r"\b\d{8}[A-Z]\b"),
        "dni",
    ),
    # NIE español: X/Y/Z + 7 digits + letter
    (
        re.compile(r"\b[XYZ]\d{7}[A-Z]\b"),
        "nie",
    ),
    # IBAN español: ES + 22 digits
    (
        re.compile(r"\bES\d{22}\b"),
        "iban",
    ),
)


class OutputGate:
    _DEFAULT_TERMS: Final[tuple[str, ...]] = (
        "idiot",
        "stupid",
        "moron",
        "dumb",
        "imbecile",
        "loser",
        "retard",
        "you are trash",
        "fuck you",
        "idiota",
        "estupido",
        "imbecil",
        "inutil",
        "subnormal",
        "gilipollas",
        "eres basura",
        "vete a la mierda",
    )

    def __init__(self, terms: list[str] | None = None):
        source_terms = terms if terms is not None else list(self._DEFAULT_TERMS)
        cleaned_terms = [_normalize_text(term) for term in source_terms if _normalize_text(term)]
        if not cleaned_terms:
            raise ValueError("output gate terms must be non-empty")

        unique_terms = sorted(set(cleaned_terms))
        self._terms = unique_terms
        self._patterns = {term: _compile_term_pattern(term) for term in unique_terms}

    def evaluate(self, text: str) -> OutputGateVerdict | None:
        if not isinstance(text, str):
            raise ValueError("output text must be str")
        normalized = _normalize_text(text)
        if not normalized:
            return None

        matched_terms = [term for term in self._terms if self._patterns[term].search(normalized)]
        if matched_terms:
            return OutputGateVerdict(
                blocked=True,
                risk_score=100,
                confidence=1.0,
                reason=f"output toxicity detected: {matched_terms[0]}",
                tags=["output_toxicity", "critical_tag_detected"],
                violated_principle="OutputSafety",
                matched_terms=matched_terms,
            )

        for pattern, label in _PII_PATTERNS:
            if pattern.search(text):
                return OutputGateVerdict(
                    blocked=True,
                    risk_score=85,
                    confidence=0.9,
                    reason=f"sensitive data detected: {label}",
                    tags=["pii_detected", "output_sensitive_data"],
                    violated_principle="DataPrivacy",
                    matched_terms=[label],
                )

        return None
