from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypedDict

from aetherya.config import ProceduralGuardConfig
from aetherya.text_normalize import normalize_security_text


class GuardResult(TypedDict):
    risk_score: int
    confidence: float
    reason: str
    tags: list[str]


def _validate_guard_result(result: dict[str, Any]) -> GuardResult:
    if not isinstance(result, dict):
        raise ValueError("GuardResult must be dict")

    risk_score = result.get("risk_score")
    if not isinstance(risk_score, int):
        raise ValueError("risk_score must be int")

    confidence = result.get("confidence")
    if not isinstance(confidence, int | float):
        raise ValueError("confidence must be float")

    tags = result.get("tags")
    if not isinstance(tags, list):
        raise ValueError("tags must be list")
    if any(not isinstance(t, str) for t in tags):
        raise ValueError("tags must be list[str]")

    reason = result.get("reason")
    if not isinstance(reason, str):
        raise ValueError("reason must be str")

    # Devolvemos un GuardResult "tipado", no el dict original genérico
    return {
        "risk_score": risk_score,
        "confidence": float(confidence),
        "reason": reason,
        "tags": tags,
    }


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProceduralRule:
    """
    One procedural detection rule.

    Either `pattern` (regex over normalized text) or `detector` (predicate over
    normalized text) must be set. Rules carry their own severity so a single
    corpus can express "irreversible destruction" and "needs a human" without
    collapsing them onto one score.
    """

    tag: str
    risk_score: int
    confidence: float
    reason: str
    extra_tags: tuple[str, ...] = ()
    pattern: re.Pattern[str] | None = None
    detector: Callable[[str], bool] | None = None

    def matches(self, text: str) -> bool:
        if self.detector is not None:
            return self.detector(text)
        if self.pattern is not None:
            return bool(self.pattern.search(text))
        return False

    def tags(self) -> list[str]:
        return [*self.extra_tags, self.tag]


# Severity constants. `critical_tag_detected` is a hard-deny tag in the default
# aggregator config, so it is reserved for irreversible destruction.
_CRITICAL_TAG = "critical_tag_detected"
_CRITICAL_REASON = "destructive system command"
_CRITICAL_RISK = 100
_CRITICAL_CONFIDENCE = 1.0

_PRIVILEGED_RISK = 45
_PRIVILEGED_CONFIDENCE = 0.65
_PRIVILEGED_REASON = "privileged package removal"


def _critical(
    tag: str,
    *,
    pattern: str | None = None,
    detector: Callable[[str], bool] | None = None,
    extra_tags: tuple[str, ...] = ("data_destruction",),
) -> ProceduralRule:
    return ProceduralRule(
        tag=tag,
        risk_score=_CRITICAL_RISK,
        confidence=_CRITICAL_CONFIDENCE,
        reason=_CRITICAL_REASON,
        extra_tags=(_CRITICAL_TAG, *extra_tags),
        pattern=re.compile(pattern) if pattern else None,
        detector=detector,
    )


# ---------------------------------------------------------------------------
# `rm` invocation analysis
#
# A regex alone cannot express "recursive AND force AND a root-like target"
# across arbitrary flag orderings (-rf, -fr, -r -f, --recursive --force).
# We locate the invocation with a regex and classify the flags in Python.
# ---------------------------------------------------------------------------

_RM_CALL_RE = re.compile(r"\brm\b(?P<rest>(?:\s+\S+)*)")
_FLAG_TOKEN_RE = re.compile(r"^-{1,2}[a-z0-9][a-z0-9-]*$")

# Top-level directories whose recursive deletion is functionally equivalent to
# destroying the host.
_ROOT_LIKE_TARGETS: frozenset[str] = frozenset(
    {
        "/",
        "/*",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/opt",
        "/proc",
        "/root",
        "/sbin",
        "/srv",
        "/sys",
        "/usr",
        "/var",
    }
)


@dataclass(frozen=True)
class _RmInvocation:
    recursive: bool
    force: bool
    no_preserve_root: bool
    targets: list[str] = field(default_factory=list)


def _strip_target(token: str) -> str:
    """Drop trailing shell/prose punctuation so `/etc;` and `/etc/` normalize."""
    cleaned = token.rstrip(".,;:!?)\"'")
    if len(cleaned) > 1:
        cleaned = cleaned.rstrip("/")
    return cleaned or "/"


def _is_path_like(token: str) -> bool:
    return token.startswith(("/", "./", "../", "~/")) or token in {"*", "~"}


def _parse_rm_invocations(text: str) -> list[_RmInvocation]:
    invocations: list[_RmInvocation] = []
    for match in _RM_CALL_RE.finditer(text):
        rest = match.group("rest") or ""
        recursive = False
        force = False
        no_preserve_root = False
        targets: list[str] = []

        for token in rest.split():
            if _FLAG_TOKEN_RE.match(token):
                if token.startswith("--"):
                    if token == "--recursive":
                        recursive = True
                    elif token == "--force":
                        force = True
                    elif token == "--no-preserve-root":
                        no_preserve_root = True
                else:
                    cluster = token[1:]
                    if "r" in cluster:
                        recursive = True
                    if "f" in cluster:
                        force = True
                continue
            # A non-flag token that does not look like a path ends the
            # invocation — prose such as "rm -rf do?" carries no target.
            if _is_path_like(token):
                targets.append(token)
            else:
                break

        invocations.append(
            _RmInvocation(
                recursive=recursive,
                force=force,
                no_preserve_root=no_preserve_root,
                targets=targets,
            )
        )
    return invocations


def _detect_root_recursive_delete(text: str) -> bool:
    for inv in _parse_rm_invocations(text):
        if not (inv.recursive and inv.force):
            continue
        if inv.no_preserve_root and inv.targets:
            return True
        if any(_strip_target(t) in _ROOT_LIKE_TARGETS for t in inv.targets):
            return True
    return False


def _detect_recursive_force_delete(text: str) -> bool:
    """Recursive+force delete of a non-root path — dangerous, but recoverable."""
    for inv in _parse_rm_invocations(text):
        if not (inv.recursive and inv.force and inv.targets):
            continue
        if inv.no_preserve_root:
            continue
        if not any(_strip_target(t) in _ROOT_LIKE_TARGETS for t in inv.targets):
            return True
    return False


# ---------------------------------------------------------------------------
# Rule families
#
# Keyed by the literal that appears in `procedural_guard.critical_tags` in
# policy.yaml. A configured entry with no registered family degrades to plain
# substring matching, so custom operator entries keep working unchanged.
# ---------------------------------------------------------------------------

_BLOCK_DEVICE = r"/dev/(?:sd|nvme|hd|vd|xvd|mmcblk|disk|loop)\S*"

_CRITICAL_FAMILIES: dict[str, tuple[ProceduralRule, ...]] = {
    "rm -rf /": (_critical("root_recursive_delete", detector=_detect_root_recursive_delete),),
    "mkfs": (
        # Requires a device argument: "explain what mkfs does" must not match.
        _critical("filesystem_format", pattern=r"\bmkfs(?:\.[a-z0-9]+)?\b[^|;&]{0,80}?/dev/\S+"),
    ),
    ":(){:|:&};:": (
        _critical(
            "fork_bomb",
            pattern=r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            extra_tags=("resource_exhaustion",),
        ),
    ),
    "block_device_write": (
        _critical(
            "block_device_overwrite",
            pattern=rf"\bdd\b[^|;&]{{0,120}}?\bof\s*=\s*{_BLOCK_DEVICE}",
        ),
        _critical("block_device_redirect", pattern=rf">\s*{_BLOCK_DEVICE}"),
        _critical(
            "block_device_wipe",
            # `[^|;&]` keeps the match inside one command; flags may carry values
            # ("shred -n 3 /dev/sda") so options are not enumerated individually.
            pattern=r"\b(?:shred|wipefs)\b[^|;&]{0,60}?\s/dev/\S+",
        ),
        _critical(
            # Any write path to a raw device destroys it as thoroughly as dd.
            "block_device_write_tool",
            pattern=r"\b(?:tee|truncate)\b[^|;&]{0,60}?\s/dev/\S+",
        ),
    ),
    "interpreter_destruction": (
        _critical(
            # Destruction embedded in an interpreter one-liner bypasses every
            # shell-command rule. Anchored on the destructive call and its
            # root argument rather than on the interpreter, so it holds whether
            # the code arrives via `python -c`, a heredoc, or a script body.
            "interpreter_recursive_delete",
            pattern=r"\brmtree\s*\(\s*/",
        ),
    ),
    "find_delete": (
        _critical(
            "find_delete_root",
            pattern=r"\bfind\s+/\s[^|;&]{0,80}?-delete\b",
        ),
    ),
}

_ELEVATED_FAMILIES: dict[str, tuple[ProceduralRule, ...]] = {
    "recursive_force_delete": (
        ProceduralRule(
            tag="recursive_force_delete",
            risk_score=55,
            confidence=0.85,
            reason="recursive force delete of a non-root path",
            extra_tags=("data_destruction",),
            detector=_detect_recursive_force_delete,
        ),
    ),
    "remote_code_execution": (
        ProceduralRule(
            tag="remote_code_execution",
            risk_score=70,
            confidence=0.9,
            reason="remote script piped into a shell",
            extra_tags=("system_change",),
            pattern=re.compile(r"\b(?:curl|wget)\b[^|;&]{0,200}\|\s*(?:sudo\s+)?[a-z]{0,3}sh\b"),
        ),
    ),
}

# Regex upgrades for the default `privileged_ops` literals. Same severity and
# reason as before — only the matching is sharpened.
_PRIVILEGED_PATTERNS: dict[str, str] = {
    "apt remove": r"\bapt(?:-get)?\s+remove\b",
    "apt purge": r"\bapt(?:-get)?\s+purge\b",
    "userdel": r"\buserdel\b",
    "chmod -r 777 /": r"\bchmod\s+-r\s+777\s+/",
}


def _privileged_rule(literal: str) -> ProceduralRule:
    pattern = _PRIVILEGED_PATTERNS.get(literal)
    return ProceduralRule(
        tag="system_change",
        risk_score=_PRIVILEGED_RISK,
        confidence=_PRIVILEGED_CONFIDENCE,
        reason=_PRIVILEGED_REASON,
        pattern=re.compile(pattern) if pattern else re.compile(re.escape(literal)),
    )


def _literal_critical_rule(literal: str) -> ProceduralRule:
    """Fallback for operator-defined entries with no registered family."""
    return _critical("critical_literal_match", pattern=re.escape(literal))


class ProceduralGuard:
    """
    Detects irreversible or privileged system operations in raw input.

    Matching runs over `normalize_security_text`, the same canonical form the
    JailbreakGuard uses, so zero-width and diacritic obfuscation cannot split a
    command token. All matching rules are collected; the highest-severity one
    sets score/reason and every matched tag is preserved for the audit trace.
    """

    def __init__(self, cfg: ProceduralGuardConfig) -> None:
        self.cfg = cfg
        self._critical_rules = self._build_critical_rules()
        self._privileged_rules = [
            _privileged_rule(str(op).strip().lower())
            for op in (getattr(cfg, "privileged_ops", []) or [])
            if str(op).strip()
        ]

    def _build_critical_rules(self) -> list[ProceduralRule]:
        rules: list[ProceduralRule] = []
        for raw in getattr(self.cfg, "critical_tags", []) or []:
            key = str(raw).strip().lower()
            if not key:
                continue
            if key in _CRITICAL_FAMILIES:
                rules.extend(_CRITICAL_FAMILIES[key])
            elif key in _ELEVATED_FAMILIES:
                rules.extend(_ELEVATED_FAMILIES[key])
            else:
                rules.append(_literal_critical_rule(key))
        return rules

    def evaluate(self, text: str) -> GuardResult | None:
        normalized = normalize_security_text(text)
        if not normalized:
            return None

        matched: list[ProceduralRule] = [r for r in self._critical_rules if r.matches(normalized)]

        # Privileged operations keep their historical contract: the literal must
        # appear alongside an explicit privilege escalation.
        if "sudo" in normalized:
            matched.extend(r for r in self._privileged_rules if r.matches(normalized))

        if not matched:
            return None

        top = max(matched, key=lambda r: (r.risk_score, r.confidence))

        tags: list[str] = []
        for rule in matched:
            for tag in rule.tags():
                if tag not in tags:
                    tags.append(tag)

        return _validate_guard_result(
            {
                "risk_score": top.risk_score,
                "reason": top.reason,
                "tags": tags,
                "confidence": top.confidence,
            }
        )
