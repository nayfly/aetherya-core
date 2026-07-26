from __future__ import annotations

import re
import unicodedata

_WHITESPACE_RE = re.compile(r"\s+")


def normalize_security_text(text: str) -> str:
    """
    Normalize text before security pattern matching.

    Pipeline: lowercase -> NFKD decomposition -> strip combining characters and
    Unicode format characters -> compact whitespace.

    This eliminates:
    - Zero-width chars (U+200B/C/D, U+FEFF, etc.) - Unicode category 'Cf'
    - Diacritic variants (ignore -> ignore, Einschraenkungen -> einschrankungen)
    - Fullwidth char decompositions via NFKD

    It does NOT handle ASCII l33tspeak (1gn0r3) - that substitution step
    carries meaningful false-positive risk for legitimate inputs.

    Shared by JailbreakGuard and ProceduralGuard so both see the same
    canonical form; a bypass fixed in one is fixed in the other.
    """
    lowered = text.lower()
    folded = unicodedata.normalize("NFKD", lowered)
    # Strip combining diacritics AND Unicode format/invisible characters (category Cf).
    # Category Cf covers: zero-width space (U+200B), zero-width non-joiner (U+200C),
    # zero-width joiner (U+200D), BOM (U+FEFF), soft hyphen (U+00AD), etc.
    stripped = "".join(
        ch for ch in folded if not unicodedata.combining(ch) and unicodedata.category(ch) != "Cf"
    )
    return _WHITESPACE_RE.sub(" ", stripped).strip()
