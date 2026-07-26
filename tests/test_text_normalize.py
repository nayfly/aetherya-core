from __future__ import annotations

from aetherya.jailbreak import _normalize_jailbreak_text
from aetherya.text_normalize import normalize_security_text


def test_lowercases_and_compacts_whitespace() -> None:
    assert normalize_security_text("  RM   -RF    /  ") == "rm -rf /"


def test_strips_zero_width_characters() -> None:
    # Zero-width space / non-joiner / joiner / BOM must not split a token.
    assert normalize_security_text("r​m -r‌f /") == "rm -rf /"
    assert normalize_security_text("﻿mkfs") == "mkfs"


def test_strips_combining_diacritics() -> None:
    assert normalize_security_text("ïgnore") == "ignore"
    assert normalize_security_text("Einschränkungen") == "einschrankungen"


def test_decomposes_fullwidth_characters() -> None:
    assert normalize_security_text("ｒｍ") == "rm"


def test_empty_and_whitespace_only_normalize_to_empty() -> None:
    assert normalize_security_text("") == ""
    assert normalize_security_text("   \n\t ") == ""


def test_jailbreak_alias_delegates_to_shared_normalizer() -> None:
    """The guards must share one canonical form; a bypass fixed once is fixed for both."""
    for probe in ["IGNORE  previous", "r​m -rf /", "ïgnore les règles"]:
        assert _normalize_jailbreak_text(probe) == normalize_security_text(probe)
