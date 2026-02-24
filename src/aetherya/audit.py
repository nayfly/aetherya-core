import json
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    event_id: str
    ts: str
    actor: str
    action: str
    decision: dict[str, Any]
    context: dict[str, Any]


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
        ev = AuditEvent(
            event_id=str(uuid.uuid4()),
            ts=datetime.now(UTC).isoformat(),
            actor=actor,
            action=action,
            decision=decision,
            context=context or {},
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
        return ev
