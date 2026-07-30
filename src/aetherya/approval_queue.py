from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

# ---------------------------------------------------------------------------
# Held actions waiting on a human.
#
# Phase 3 holds `escalate` for confirmation, and the engine already mints and
# verifies the proof that unblocks one. What has never existed is the place in
# between: somewhere an agent can park a held action and somewhere an operator
# can answer it. Without that, phase 3 either refuses escalations outright or
# the integrator invents their own channel.
#
# Requests are durable because an approval is a decision about a real action:
# restarting the service must not silently discard a queue of things people are
# waiting on. They expire because an approval nobody answers has to become a
# refusal rather than a process that hangs forever — abandonment is a number the
# rollout plan asks you to watch, and it can only be measured if it is recorded.
#
# See docs/rollout-phases.md#phase-3--full-enforcement.
# ---------------------------------------------------------------------------

PENDING: Final = "pending"
APPROVED: Final = "approved"
REJECTED: Final = "rejected"
EXPIRED: Final = "expired"

DEFAULT_TTL_SECONDS: Final = 900


class ApprovalQueueError(RuntimeError):
    """The request cannot be moved to the state asked for."""


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    actor: str
    action: dict[str, Any]
    state: str
    risk_score: int
    reason: str
    requested_at: str
    expires_at: str
    status: str = PENDING
    decided_by: str | None = None
    decided_at: str | None = None
    note: str = ""
    # Present only once approved. Single-use by policy, so it is handed to the
    # agent and never stored anywhere it could be replayed from.
    proof: str | None = None

    def to_dict(self, *, include_proof: bool = False) -> dict[str, Any]:
        payload = {
            "request_id": self.request_id,
            "actor": self.actor,
            "action": self.action,
            "state": self.state,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "note": self.note,
        }
        if include_proof and self.proof:
            payload["proof"] = self.proof
        return payload


def _now() -> datetime:
    return datetime.now(UTC)


def _parse(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _as_request(payload: object) -> ApprovalRequest | None:
    """
    One place that turns a recorded line into a request.

    Both the current-state view and the history need this, and two copies would
    drift — the kind of divergence where a field is read in one view and lost in
    the other without anything failing.
    """
    if not isinstance(payload, dict):
        return None
    request_id = str(payload.get("request_id", "")).strip()
    if not request_id:
        return None
    action = payload.get("action")
    try:
        return ApprovalRequest(
            request_id=request_id,
            actor=str(payload.get("actor", "unknown")),
            action=action if isinstance(action, dict) else {},
            state=str(payload.get("state", "unknown")),
            risk_score=int(payload.get("risk_score", 0) or 0),
            reason=str(payload.get("reason", "")),
            requested_at=str(payload.get("requested_at", "")),
            expires_at=str(payload.get("expires_at", "")),
            status=str(payload.get("status", PENDING)),
            decided_by=payload.get("decided_by"),
            decided_at=payload.get("decided_at"),
            note=str(payload.get("note", "")),
        )
    except (TypeError, ValueError):
        return None


def _read_lines(path: Path) -> Iterator[ApprovalRequest]:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        request = _as_request(payload)
        if request is not None:
            yield request


class ApprovalQueue:
    """
    Durable queue of held actions, one JSONL of state transitions.

    Append-only like the review store and for the same reason: an approval is a
    human act with consequences, so who answered what and when has to survive.
    The current state of a request is the last transition recorded for it.
    """

    def __init__(self, path: str | Path, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.path = Path(path)
        self.ttl_seconds = max(int(ttl_seconds), 1)
        self._lock = threading.Lock()

    # -- writing --------------------------------------------------------------

    def submit(
        self,
        *,
        actor: str,
        action: dict[str, Any],
        state: str,
        risk_score: int,
        reason: str,
    ) -> ApprovalRequest:
        actor = str(actor).strip()
        if not actor:
            raise ValueError("actor must be non-empty")
        if not isinstance(action, dict) or not action:
            raise ValueError("action must be a non-empty object")

        now = _now()
        request = ApprovalRequest(
            request_id=f"apr_{uuid.uuid4().hex[:16]}",
            actor=actor,
            action=action,
            state=str(state),
            risk_score=int(risk_score),
            reason=str(reason)[:1000],
            requested_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat(),
        )
        self._append(request)
        return request

    def resolve(
        self,
        request_id: str,
        *,
        approved: bool,
        decided_by: str,
        note: str = "",
        proof: str | None = None,
    ) -> ApprovalRequest:
        decided_by = str(decided_by).strip()
        if not decided_by:
            raise ValueError("decided_by must be non-empty")

        note = str(note).strip()
        # A rejection is the operator overriding what the agent wanted to do.
        # The reason is what the agent's owner will ask for, and what tells you
        # later whether the escalation was worth surfacing at all.
        if not approved and not note:
            raise ValueError("a rejection must explain why")

        with self._lock:
            current = self._current().get(request_id)
            if current is None:
                raise ApprovalQueueError(f"no approval request {request_id!r}")
            if current.status != PENDING:
                raise ApprovalQueueError(
                    f"request {request_id!r} is already {current.status}; "
                    "an answered request cannot be answered again"
                )
            if self._is_expired(current):
                # Recorded as expired rather than silently approved: the operator
                # is answering something the agent stopped waiting for.
                self._append_locked(self._expire(current))
                raise ApprovalQueueError(
                    f"request {request_id!r} expired at {current.expires_at} "
                    "— the agent is no longer waiting, so it must be re-requested"
                )

            resolved = ApprovalRequest(
                **{
                    **current.to_dict(),
                    "status": APPROVED if approved else REJECTED,
                    "decided_by": decided_by,
                    "decided_at": _now().isoformat(),
                    "note": note[:2000],
                    "proof": proof if approved else None,
                }
            )
            self._append_locked(resolved)
            return resolved

    def _append(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._append_locked(request)

    def _append_locked(self, request: ApprovalRequest) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            # The proof is never written down. It is single-use, so a copy on
            # disk is a replayable credential sitting next to the record of what
            # it authorises.
            handle.write(json.dumps(request.to_dict(), ensure_ascii=False) + "\n")

    # -- reading --------------------------------------------------------------

    def _current(self) -> dict[str, ApprovalRequest]:
        """Last recorded transition per request — its present state."""
        return {request.request_id: request for request in _read_lines(self.path)}

    def _is_expired(self, request: ApprovalRequest) -> bool:
        deadline = _parse(request.expires_at)
        return deadline is not None and _now() >= deadline

    def _expire(self, request: ApprovalRequest) -> ApprovalRequest:
        return ApprovalRequest(
            **{
                **request.to_dict(),
                "status": EXPIRED,
                "decided_at": _now().isoformat(),
                "note": "expired without an answer",
            }
        )

    def pending(self) -> list[ApprovalRequest]:
        """
        Requests still waiting, oldest first — the order to work through them.

        Expiry is materialised here rather than by a background sweeper: the
        queue has no process of its own, and a request that is read as pending
        after its deadline would be answerable long after the agent gave up.
        """
        with self._lock:
            live: list[ApprovalRequest] = []
            for request in self._current().values():
                if request.status != PENDING:
                    continue
                if self._is_expired(request):
                    self._append_locked(self._expire(request))
                    continue
                live.append(request)
        return sorted(live, key=lambda r: r.requested_at)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Current state of one request, for an agent polling its own."""
        with self._lock:
            request = self._current().get(request_id)
            if request is not None and request.status == PENDING and self._is_expired(request):
                expired = self._expire(request)
                self._append_locked(expired)
                return expired
        return request

    def history(self) -> list[ApprovalRequest]:
        """Every recorded transition, in file order, including superseded ones."""
        return list(_read_lines(self.path))

    def stats(self) -> dict[str, int]:
        """Counts by status — the abandonment rate phase 3 asks you to watch."""
        counts: dict[str, int] = {PENDING: 0, APPROVED: 0, REJECTED: 0, EXPIRED: 0}
        for request in self._current().values():
            status = request.status
            if request.status == PENDING and self._is_expired(request):
                status = EXPIRED
            counts[status] = counts.get(status, 0) + 1
        return counts


@dataclass
class QueueSettings:
    path: Path = field(default_factory=lambda: Path("audit/approvals.jsonl"))
    ttl_seconds: int = DEFAULT_TTL_SECONDS
