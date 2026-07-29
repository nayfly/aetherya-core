from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from aetherya.approval_queue import (
    APPROVED,
    EXPIRED,
    PENDING,
    REJECTED,
    ApprovalQueue,
    ApprovalQueueError,
)

ACTION = {"raw_input": "write /srv/app/config.PROD.yaml", "tool": "filesystem"}


def _queue(tmp_path: Path, ttl: int = 900) -> ApprovalQueue:
    return ApprovalQueue(tmp_path / "approvals.jsonl", ttl_seconds=ttl)


def _submit(queue: ApprovalQueue, actor: str = "agent-a") -> str:
    return queue.submit(
        actor=actor,
        action=ACTION,
        state="escalate",
        risk_score=63,
        reason="escalate: strong confirmation evidence is missing",
    ).request_id


# ---------------------------------------------------------------------------
# Submitting
# ---------------------------------------------------------------------------


def test_a_held_action_becomes_a_pending_request(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    request = queue.submit(
        actor="agent-a", action=ACTION, state="escalate", risk_score=63, reason="needs a human"
    )

    assert request.status == PENDING
    assert request.request_id.startswith("apr_")
    assert request.expires_at > request.requested_at
    assert [r.request_id for r in queue.pending()] == [request.request_id]


def test_pending_requests_come_oldest_first(tmp_path: Path) -> None:
    """The order to work through them: the agent waiting longest goes first."""
    queue = _queue(tmp_path)
    ids = [_submit(queue, f"agent-{index}") for index in range(3)]
    assert [r.request_id for r in queue.pending()] == ids


def test_the_queue_survives_a_restart(tmp_path: Path) -> None:
    """An approval is about a real action; a restart must not discard the queue."""
    request_id = _submit(_queue(tmp_path))
    assert [r.request_id for r in _queue(tmp_path).pending()] == [request_id]


@pytest.mark.parametrize(
    ("actor", "action", "match"),
    [
        ("", ACTION, "actor"),
        ("   ", ACTION, "actor"),
        ("a", {}, "non-empty object"),
        ("a", None, "non-empty object"),
    ],
)
def test_malformed_submissions_are_rejected(
    tmp_path: Path, actor: str, action: object, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        _queue(tmp_path).submit(
            actor=actor,
            action=action,  # type: ignore[arg-type]
            state="escalate",
            risk_score=0,
            reason="x",
        )


# ---------------------------------------------------------------------------
# Answering
# ---------------------------------------------------------------------------


def test_approving_records_who_answered(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    request_id = _submit(queue)

    resolved = queue.resolve(request_id, approved=True, decided_by="robert", proof="ack:abc12345")
    assert resolved.status == APPROVED
    assert resolved.decided_by == "robert"
    assert resolved.decided_at
    assert queue.pending() == []


def test_the_proof_reaches_the_agent_but_is_never_written_down(tmp_path: Path) -> None:
    """
    A signed proof is single-use, so a copy on disk is a replayable credential
    filed next to the record of what it authorises.
    """
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    resolved = queue.resolve(request_id, approved=True, decided_by="robert", proof="secret-proof")

    assert resolved.proof == "secret-proof"
    assert "secret-proof" not in queue.path.read_text(encoding="utf-8")
    # And it is not recoverable by reading the queue back.
    assert queue.get(request_id) is not None
    assert queue.get(request_id).proof is None  # type: ignore[union-attr]


def test_a_rejection_must_explain_itself(tmp_path: Path) -> None:
    """The operator is overriding the agent; the reason is what gets asked for."""
    queue = _queue(tmp_path)
    request_id = _submit(queue)

    with pytest.raises(ValueError, match="must explain why"):
        queue.resolve(request_id, approved=False, decided_by="robert")
    with pytest.raises(ValueError, match="must explain why"):
        queue.resolve(request_id, approved=False, decided_by="robert", note="   ")


def test_a_rejection_with_a_reason_is_recorded(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    request_id = _submit(queue)

    resolved = queue.resolve(
        request_id, approved=False, decided_by="robert", note="wrong environment, that is PROD"
    )
    assert resolved.status == REJECTED
    assert resolved.proof is None
    assert "wrong environment" in resolved.note


def test_an_approval_needs_a_named_operator(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    with pytest.raises(ValueError, match="decided_by"):
        queue.resolve(request_id, approved=True, decided_by="  ")


def test_an_unknown_request_cannot_be_answered(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueError, match="no approval request"):
        _queue(tmp_path).resolve("apr_nope", approved=True, decided_by="robert")


def test_a_request_cannot_be_answered_twice(tmp_path: Path) -> None:
    """
    Double-answering would mint a second proof for one authorisation, which is
    the replay the single-use rule exists to prevent.
    """
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    queue.resolve(request_id, approved=True, decided_by="robert", proof="p1")

    with pytest.raises(ApprovalQueueError, match="already approved"):
        queue.resolve(request_id, approved=True, decided_by="robert", proof="p2")
    with pytest.raises(ApprovalQueueError, match="already approved"):
        queue.resolve(request_id, approved=False, decided_by="robert", note="changed my mind")


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_an_unanswered_request_expires(tmp_path: Path) -> None:
    """
    An approval nobody answers has to become a refusal. A request that stayed
    pending forever is an agent hanging forever.
    """
    queue = ApprovalQueue(tmp_path / "approvals.jsonl", ttl_seconds=1)
    request_id = _submit(queue)
    queue.path.write_text(_with_expiry(queue.path, "2020-01-01T00:00:00+00:00"), encoding="utf-8")

    assert queue.pending() == []
    assert queue.get(request_id).status == EXPIRED  # type: ignore[union-attr]


def test_expiry_is_recorded_not_inferred(tmp_path: Path) -> None:
    """
    Abandonment is a number the rollout plan asks you to watch, and it can only
    be counted if the transition is written down.
    """
    queue = _queue(tmp_path)
    _submit(queue)
    queue.path.write_text(_with_expiry(queue.path, "2020-01-01T00:00:00+00:00"), encoding="utf-8")
    queue.pending()

    statuses = [r.status for r in queue.history()]
    assert statuses[-1] == EXPIRED
    assert queue.stats()[EXPIRED] == 1


def test_an_expired_request_cannot_be_approved(tmp_path: Path) -> None:
    """The agent stopped waiting; approving now authorises nothing."""
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    queue.path.write_text(_with_expiry(queue.path, "2020-01-01T00:00:00+00:00"), encoding="utf-8")

    with pytest.raises(ApprovalQueueError, match="expired"):
        queue.resolve(request_id, approved=True, decided_by="robert", proof="p")
    assert queue.get(request_id).status == EXPIRED  # type: ignore[union-attr]


def test_an_unparseable_deadline_does_not_expire_a_request(tmp_path: Path) -> None:
    """Fail towards the human: a corrupt timestamp must not silently drop work."""
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    queue.path.write_text(_with_expiry(queue.path, "not-a-date"), encoding="utf-8")

    assert [r.request_id for r in queue.pending()] == [request_id]


def _with_expiry(path: Path, expires_at: str) -> str:
    """Rewrite every recorded line with a new deadline."""
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        payload["expires_at"] = expires_at
        lines.append(json.dumps(payload))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def test_the_store_is_append_only(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    queue.resolve(request_id, approved=True, decided_by="robert", proof="p")

    history = queue.history()
    assert [r.status for r in history] == [PENDING, APPROVED]
    assert queue.get(request_id).status == APPROVED  # type: ignore[union-attr]


def test_stats_count_by_status(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    approved = _submit(queue, "a")
    rejected = _submit(queue, "b")
    _submit(queue, "c")

    queue.resolve(approved, approved=True, decided_by="robert", proof="p")
    queue.resolve(rejected, approved=False, decided_by="robert", note="not in PROD")

    assert queue.stats() == {PENDING: 1, APPROVED: 1, REJECTED: 1, EXPIRED: 0}


def test_an_empty_queue_reads_as_empty(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    assert queue.pending() == []
    assert queue.history() == []
    assert queue.get("apr_anything") is None
    assert queue.stats()[PENDING] == 0


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    with queue.path.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
        handle.write("\n")
        handle.write('"bare string"\n')
        handle.write(json.dumps({"actor": "no id here"}) + "\n")
        handle.write(json.dumps({"request_id": "   "}) + "\n")

    assert [r.request_id for r in queue.pending()] == [request_id]


def test_a_request_missing_optional_fields_still_loads(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    queue.path.parent.mkdir(parents=True, exist_ok=True)
    queue.path.write_text(
        json.dumps({"request_id": "apr_bare", "expires_at": "2999-01-01T00:00:00+00:00"}) + "\n",
        encoding="utf-8",
    )

    request = queue.get("apr_bare")
    assert request is not None
    assert request.actor == "unknown"
    assert request.action == {}
    assert request.status == PENDING


def test_a_non_numeric_risk_score_does_not_break_the_queue(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    queue.path.parent.mkdir(parents=True, exist_ok=True)
    queue.path.write_text(
        json.dumps({"request_id": "apr_x", "risk_score": "high"}) + "\n", encoding="utf-8"
    )
    assert queue.history() == []


def test_the_parent_directory_is_created(tmp_path: Path) -> None:
    queue = ApprovalQueue(tmp_path / "nested" / "deeper" / "approvals.jsonl")
    _submit(queue)
    assert queue.path.exists()


def test_a_ttl_below_one_second_is_clamped(tmp_path: Path) -> None:
    """A zero TTL would expire every request before anyone could see it."""
    assert ApprovalQueue(tmp_path / "a.jsonl", ttl_seconds=0).ttl_seconds == 1
    assert ApprovalQueue(tmp_path / "b.jsonl", ttl_seconds=-5).ttl_seconds == 1


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_only_one_of_two_racing_approvals_wins(tmp_path: Path) -> None:
    """
    Two operators clicking approve on the same request must not both succeed:
    that mints two proofs for one authorisation.
    """
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    outcomes: list[str] = []

    def approve() -> None:
        try:
            queue.resolve(request_id, approved=True, decided_by="robert", proof="p")
            outcomes.append("won")
        except ApprovalQueueError:
            outcomes.append("lost")

    threads = [threading.Thread(target=approve) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("won") == 1
    assert outcomes.count("lost") == 7


def test_stats_report_an_overdue_request_as_expired(tmp_path: Path) -> None:
    """
    The count has to reflect reality even before anything materialised the
    transition, or the abandonment number lags behind whoever last read it.
    """
    queue = _queue(tmp_path)
    _submit(queue)
    queue.path.write_text(_with_expiry(queue.path, "2020-01-01T00:00:00+00:00"), encoding="utf-8")

    assert queue.stats() == {PENDING: 0, APPROVED: 0, REJECTED: 0, EXPIRED: 1}


def test_getting_an_overdue_request_records_the_expiry(tmp_path: Path) -> None:
    """A poll is the agent asking; that is the moment it learns it gave up."""
    queue = _queue(tmp_path)
    request_id = _submit(queue)
    queue.path.write_text(_with_expiry(queue.path, "2020-01-01T00:00:00+00:00"), encoding="utf-8")

    assert queue.get(request_id).status == EXPIRED  # type: ignore[union-attr]
    assert [r.status for r in queue.history()][-1] == EXPIRED
