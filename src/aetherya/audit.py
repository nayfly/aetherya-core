import hashlib
import hmac
import json
import math
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock
    fcntl = None  # type: ignore[assignment]


@dataclass
class AuditEvent:
    event_id: str
    decision_id: str
    context_hash: str
    prev_chain_hash: str | None
    chain_hash: str
    policy_fingerprint: str | None
    attestation_alg: str
    attestation: str
    ts: str
    actor: str
    action: str
    decision: dict[str, Any]
    context: dict[str, Any]


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    errors: list[str]
    expected_context_hash: str
    expected_decision_id: str
    expected_attestation_alg: str
    expected_attestation: str


def _normalize_for_hash(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value

    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return str(value)

    if isinstance(value, dict):
        return {str(k): _normalize_for_hash(v) for k, v in value.items()}

    if isinstance(value, list | tuple):
        return [_normalize_for_hash(v) for v in value]

    if isinstance(value, set):
        normalized_items = [_normalize_for_hash(v) for v in value]
        return sorted(
            normalized_items,
            key=lambda item: json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )

    return f"<{type(value).__module__}.{type(value).__qualname__}>"


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        _normalize_for_hash(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _resolve_attestation_key(explicit_key: str | None) -> bytes | None:
    raw = explicit_key if explicit_key is not None else os.getenv("AETHERYA_ATTESTATION_KEY", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned.encode("utf-8") if cleaned else None


def _clean_policy_fingerprint(value: Any) -> str | None:
    cleaned = value.strip() if isinstance(value, str) else ""
    return cleaned if cleaned else None


def _safe_dict_payload(value: Any) -> dict[str, Any]:
    normalized = _normalize_for_hash(value)
    if isinstance(normalized, dict):
        return normalized
    return {"value": normalized}


def _materialize_hashes(
    *,
    actor: Any,
    action: Any,
    decision: Any,
    context: Any,
    policy_fingerprint: str | None,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    safe_context = _safe_dict_payload(context or {})
    safe_decision = _safe_dict_payload(decision)

    if policy_fingerprint:
        safe_context = {**safe_context, "policy_fingerprint": policy_fingerprint}

    context_hash = f"sha256:{_sha256_hex(_canonical_json(safe_context))}"
    decision_material = {
        "actor": actor,
        "action": action,
        "decision": safe_decision,
        "context_hash": context_hash,
        "policy_fingerprint": policy_fingerprint,
    }
    decision_id = f"sha256:{_sha256_hex(_canonical_json(decision_material))}"
    return safe_decision, safe_context, context_hash, decision_id


def _build_attestation(
    *,
    decision_id: str,
    policy_fingerprint: str | None,
    attestation_key: bytes | None,
) -> tuple[str, str]:
    attestation_material = {
        "decision_id": decision_id,
        "policy_fingerprint": policy_fingerprint,
    }
    attestation_payload = _canonical_json(attestation_material).encode("utf-8")
    if attestation_key:
        attestation_alg = "hmac-sha256"
        attestation_digest = hmac.new(
            attestation_key, attestation_payload, digestmod=hashlib.sha256
        ).hexdigest()
        return attestation_alg, f"{attestation_alg}:{attestation_digest}"

    attestation_alg = "sha256"
    attestation = f"{attestation_alg}:{hashlib.sha256(attestation_payload).hexdigest()}"
    return attestation_alg, attestation


def materialize_chain_hash(
    *,
    prev_chain_hash: str | None,
    decision_id: str,
    context_hash: str,
    attestation: str,
    actor: Any,
    action: Any,
    ts: str,
) -> str:
    chain_material = {
        "prev_chain_hash": prev_chain_hash,
        "decision_id": decision_id,
        "context_hash": context_hash,
        "attestation": attestation,
        "actor": actor,
        "action": action,
        "ts": ts,
    }
    return f"sha256:{_sha256_hex(_canonical_json(chain_material))}"


@contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """
    Hold an exclusive lock on the audit file for the duration of a write.

    A hash chain is a sequence, so two writers appending concurrently produce
    events whose `prev_chain_hash` does not name the line before them and the
    whole file fails verification. That happens silently: both processes think
    they succeeded, and nothing surfaces until someone runs `audit verify`.

    The lock lives in a sidecar `.lock` file rather than on the JSONL itself, so
    a reader that opens the trail is never blocked by a writer and vice versa.
    Where flock is unavailable the lock degrades to a no-op — single-writer
    deployments are unaffected, and multi-writer ones were already broken there.
    """
    if fcntl is None:  # pragma: no cover - platform without flock
        yield
        return
    # Deliberately does not create the parent directory. The constructor already
    # did, and creating it here would turn a write to an unwritable path into a
    # success — the failure that leaves the chain tip where it was.
    with (path.parent / f"{path.name}.lock").open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _tail_chain_tip(path: Path, *, window: int = 65_536) -> str | None:
    """
    Chain hash of the last event, read from the tail rather than the whole file.

    Called on every write once a second writer is possible, so it cannot be
    O(file). Reads a trailing window and takes the last complete line in it; if
    the window lands mid-line the partial leading fragment is discarded, and if
    no complete line fits the window is grown.
    """
    if not path.exists():
        return None
    size = path.stat().st_size
    if size == 0:
        return None

    with path.open("rb") as handle:
        while True:
            start = max(0, size - window)
            handle.seek(start)
            chunk = handle.read(size - start)
            # A window that did not start at byte 0 may open mid-line; that
            # fragment is not a whole record and must not be parsed.
            lines = chunk.split(b"\n")[1:] if start > 0 else chunk.split(b"\n")
            complete = [line for line in lines if line.strip()]
            if complete:
                try:
                    payload = json.loads(complete[-1].decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return None
                if not isinstance(payload, dict):
                    return None
                chain_hash = payload.get("chain_hash")
                cleaned = chain_hash.strip() if isinstance(chain_hash, str) else ""
                return cleaned if cleaned else None
            if start == 0:
                return None
            window *= 4


def _load_chain_tip(path: Path) -> str | None:
    if not path.exists():
        return None

    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in reversed(lines):
        if not raw.strip():
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        chain_hash = payload.get("chain_hash")
        cleaned = chain_hash.strip() if isinstance(chain_hash, str) else ""
        return cleaned if cleaned else None
    return None


def verify_audit_event(
    event: dict[str, Any], attestation_key: str | None = None
) -> AuditVerification:
    if not isinstance(event, dict):
        raise ValueError("event must be dict")

    policy_fingerprint = _clean_policy_fingerprint(event.get("policy_fingerprint"))
    _, _, expected_context_hash, expected_decision_id = _materialize_hashes(
        actor=event.get("actor"),
        action=event.get("action"),
        decision=event.get("decision"),
        context=event.get("context"),
        policy_fingerprint=policy_fingerprint,
    )
    expected_attestation_alg, expected_attestation = _build_attestation(
        decision_id=expected_decision_id,
        policy_fingerprint=policy_fingerprint,
        attestation_key=_resolve_attestation_key(attestation_key),
    )

    errors: list[str] = []

    if event.get("context_hash") != expected_context_hash:
        errors.append("context_hash mismatch")
    if event.get("decision_id") != expected_decision_id:
        errors.append("decision_id mismatch")
    if event.get("attestation_alg") != expected_attestation_alg:
        errors.append("attestation_alg mismatch")
    if event.get("attestation") != expected_attestation:
        errors.append("attestation mismatch")

    return AuditVerification(
        valid=not errors,
        errors=errors,
        expected_context_hash=expected_context_hash,
        expected_decision_id=expected_decision_id,
        expected_attestation_alg=expected_attestation_alg,
        expected_attestation=expected_attestation,
    )


class AuditSink(Protocol):
    """
    Destination for audit events beyond the primary JSONL file.

    A local file does not survive an ephemeral container and offers no
    retention. Attach a mirror that ships each event to append-only storage
    (S3 with object-lock, a WORM log service) so the chain outlives the process
    that produced it. The mirror receives the exact serialized line the primary
    wrote, so the chain hashes verify identically on either copy.
    """

    def write(self, event: AuditEvent, line: str) -> None: ...


class AuditLogger:
    """
    Append-only JSONL audit log with chain integrity.

    DURABILITY: `fsync=True` forces each event to disk before returning. Off by
    default because it costs a syscall per decision; turn it on wherever losing
    the last few events to a hard kill is unacceptable. Note that without it a
    container killed mid-write can leave the on-disk chain shorter than what the
    process believed it had written.

    RETENTION: pass `mirrors` to fan out to append-only storage. Mirror failures
    are counted in `mirror_errors` rather than raised, so a transient outage in
    the archive does not take the decision path down — monitor that counter.
    """

    def __init__(
        self,
        path: str = "./audit/decisions.jsonl",
        policy_fingerprint: str | None = None,
        attestation_key: str | None = None,
        *,
        fsync: bool = False,
        mirrors: list[AuditSink] | None = None,
    ):
        self.path = Path(path)
        self.policy_fingerprint = _clean_policy_fingerprint(policy_fingerprint)
        self.attestation_key = _resolve_attestation_key(attestation_key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._chain_tip = _load_chain_tip(self.path)
        # Size of the file as of our last write. A different size under the lock
        # means someone else appended, so our cached tip is stale. Comparing
        # sizes is one stat() and keeps the common single-writer case free.
        self._known_size = self.path.stat().st_size if self.path.exists() else 0
        self.fsync = bool(fsync)
        self.mirrors: list[AuditSink] = list(mirrors or [])
        # Mirror failures must not break decisions, but a mirror that fails
        # silently is worse than no mirror: monitor this counter.
        self.mirror_errors = 0

    def set_policy_fingerprint(self, fingerprint: str | None) -> None:
        self.policy_fingerprint = _clean_policy_fingerprint(fingerprint)

    def set_attestation_key(self, key: str | None) -> None:
        self.attestation_key = _resolve_attestation_key(key)

    def log(
        self,
        *,
        actor: str,
        action: str,
        decision: dict[str, Any],
        context: dict[str, Any] | None = None,
        policy_fingerprint: str | None = None,
    ) -> AuditEvent:
        effective_policy_fingerprint = (
            _clean_policy_fingerprint(policy_fingerprint) or self.policy_fingerprint
        )
        safe_decision, safe_context, context_hash, decision_id = _materialize_hashes(
            actor=actor,
            action=action,
            decision=decision,
            context=context,
            policy_fingerprint=effective_policy_fingerprint,
        )
        attestation_alg, attestation = _build_attestation(
            decision_id=decision_id,
            policy_fingerprint=effective_policy_fingerprint,
            attestation_key=self.attestation_key,
        )
        ts = datetime.now(UTC).isoformat()

        # Reading the tip and appending have to be one indivisible step. Split
        # them and a second writer can land in between, so both events name the
        # same predecessor and the chain no longer describes the file.
        with _exclusive(self.path):
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size != self._known_size:
                # Someone else appended since our last write. Re-read rather
                # than trust the cached tip, which now points into the middle
                # of the file.
                self._chain_tip = _tail_chain_tip(self.path)

            prev_chain_hash = self._chain_tip
            chain_hash = materialize_chain_hash(
                prev_chain_hash=prev_chain_hash,
                decision_id=decision_id,
                context_hash=context_hash,
                attestation=attestation,
                actor=actor,
                action=action,
                ts=ts,
            )

            ev = AuditEvent(
                event_id=str(uuid.uuid4()),
                decision_id=decision_id,
                context_hash=context_hash,
                prev_chain_hash=prev_chain_hash,
                chain_hash=chain_hash,
                policy_fingerprint=effective_policy_fingerprint,
                attestation_alg=attestation_alg,
                attestation=attestation,
                ts=ts,
                actor=actor,
                action=action,
                decision=safe_decision,
                context=safe_context,
            )
            line = json.dumps(asdict(ev), ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                if self.fsync:
                    f.flush()
                    os.fsync(f.fileno())

            # The chain tip only advances once the primary write succeeded — an
            # exception above leaves the tip where it was, so the next event
            # still chains onto the last durably recorded one.
            self._chain_tip = chain_hash
            self._known_size = self.path.stat().st_size

        for mirror in self.mirrors:
            try:
                mirror.write(ev, line)
            except Exception:
                self.mirror_errors += 1

        return ev
