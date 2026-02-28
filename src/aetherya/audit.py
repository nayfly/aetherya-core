import hashlib
import json
import math
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    event_id: str
    decision_id: str
    context_hash: str
    ts: str
    actor: str
    action: str
    decision: dict[str, Any]
    context: dict[str, Any]


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


class AuditLogger:
    def __init__(self, path: str = "./audit/decisions.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        *,
        actor: str,
        action: str,
        decision: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AuditEvent:
        normalized_context = _normalize_for_hash(context or {})
        safe_context = (
            normalized_context
            if isinstance(normalized_context, dict)
            else {"value": normalized_context}
        )
        normalized_decision = _normalize_for_hash(decision)
        safe_decision = (
            normalized_decision
            if isinstance(normalized_decision, dict)
            else {"value": normalized_decision}
        )

        context_hash = f"sha256:{_sha256_hex(_canonical_json(safe_context))}"
        decision_material = {
            "actor": actor,
            "action": action,
            "decision": safe_decision,
            "context_hash": context_hash,
        }
        decision_id = f"sha256:{_sha256_hex(_canonical_json(decision_material))}"

        ev = AuditEvent(
            event_id=str(uuid.uuid4()),
            decision_id=decision_id,
            context_hash=context_hash,
            ts=datetime.now(UTC).isoformat(),
            actor=actor,
            action=action,
            decision=safe_decision,
            context=safe_context,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
        return ev
