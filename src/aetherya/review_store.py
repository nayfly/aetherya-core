from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

# ---------------------------------------------------------------------------
# Human review of hard_deny events.
#
# The phase-1 exit criteria say every hard_deny must be read by a human and
# confirmed a true positive. `aetherya rollout report` could count them but
# never pass them, because a tool cannot make that judgement. This is where the
# judgement is recorded.
#
# Append-only on purpose. A review is itself a human act with consequences —
# it is what unblocks enforcement — so who said what, and when, has to survive.
# Re-reviewing an event appends a new verdict; the latest one wins on read and
# the earlier one stays on disk.
#
# See docs/rollout-phases.md#phase-1--shadow.
# ---------------------------------------------------------------------------

TRUE_POSITIVE: Final = "true_positive"
FALSE_POSITIVE: Final = "false_positive"
VERDICTS: Final[frozenset[str]] = frozenset({TRUE_POSITIVE, FALSE_POSITIVE})


@dataclass(frozen=True)
class Review:
    event_id: str
    verdict: str
    reviewer: str
    note: str
    ts: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "verdict": self.verdict,
            "reviewer": self.reviewer,
            "note": self.note,
            "ts": self.ts,
        }


class ReviewStore:
    """Append-only JSONL of human verdicts, keyed by audit `event_id`."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(
        self,
        event_id: str,
        verdict: str,
        *,
        reviewer: str,
        note: str = "",
    ) -> Review:
        event_id = str(event_id).strip()
        if not event_id:
            raise ValueError("event_id must be non-empty")
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {sorted(VERDICTS)}, got {verdict!r}")
        reviewer = str(reviewer).strip()
        if not reviewer:
            raise ValueError("reviewer must be non-empty")

        # A false positive is a claim that the engine got it wrong. Requiring a
        # reason is what makes it actionable later — the note is what tells you
        # which rule to narrow.
        note = str(note).strip()
        if verdict == FALSE_POSITIVE and not note:
            raise ValueError("a false_positive review must explain why")

        review = Review(
            event_id=event_id,
            verdict=verdict,
            reviewer=reviewer,
            note=note[:2000],
            ts=datetime.now(UTC).isoformat(),
        )
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(review.to_dict(), ensure_ascii=False) + "\n")
        return review

    def reviews(self) -> dict[str, Review]:
        """Latest verdict per event_id. A missing or unreadable file is empty."""
        latest: dict[str, Review] = {}
        if not self.path.exists():
            return latest
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            event_id = str(payload.get("event_id", "")).strip()
            verdict = str(payload.get("verdict", ""))
            if not event_id or verdict not in VERDICTS:
                continue
            latest[event_id] = Review(
                event_id=event_id,
                verdict=verdict,
                reviewer=str(payload.get("reviewer", "unknown")),
                note=str(payload.get("note", "")),
                ts=str(payload.get("ts", "")),
            )
        return latest

    def history(self) -> list[Review]:
        """Every recorded verdict in file order, including superseded ones."""
        entries: list[Review] = []
        if not self.path.exists():
            return entries
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            event_id = str(payload.get("event_id", "")).strip()
            verdict = str(payload.get("verdict", ""))
            if not event_id or verdict not in VERDICTS:
                continue
            entries.append(
                Review(
                    event_id=event_id,
                    verdict=verdict,
                    reviewer=str(payload.get("reviewer", "unknown")),
                    note=str(payload.get("note", "")),
                    ts=str(payload.get("ts", "")),
                )
            )
        return entries
