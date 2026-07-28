from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetherya.audit import AuditLogger
from aetherya.review_store import FALSE_POSITIVE, TRUE_POSITIVE, ReviewStore
from aetherya.rollout_report import build_report


def _store(tmp_path: Path) -> ReviewStore:
    return ReviewStore(tmp_path / "reviews.jsonl")


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def test_a_verdict_round_trips(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record("evt-1", TRUE_POSITIVE, reviewer="robert")

    reviews = store.reviews()
    assert reviews["evt-1"].verdict == TRUE_POSITIVE
    assert reviews["evt-1"].reviewer == "robert"
    assert reviews["evt-1"].ts


def test_the_store_is_append_only(tmp_path: Path) -> None:
    """
    A review is a human act with consequences — it is what unblocks
    enforcement. Overwriting would erase who said what and when.
    """
    store = _store(tmp_path)
    store.record("evt-1", TRUE_POSITIVE, reviewer="alice")
    store.record("evt-1", FALSE_POSITIVE, reviewer="bob", note="legitimate cleanup job")

    assert len(store.history()) == 2
    assert [r.reviewer for r in store.history()] == ["alice", "bob"]
    # Latest wins on read.
    assert store.reviews()["evt-1"].verdict == FALSE_POSITIVE


def test_a_false_positive_must_explain_itself(tmp_path: Path) -> None:
    """The note is what identifies the rule to narrow later."""
    with pytest.raises(ValueError, match="must explain why"):
        _store(tmp_path).record("evt-1", FALSE_POSITIVE, reviewer="robert")

    with pytest.raises(ValueError, match="must explain why"):
        _store(tmp_path).record("evt-1", FALSE_POSITIVE, reviewer="robert", note="   ")


def test_a_true_positive_needs_no_note(tmp_path: Path) -> None:
    assert _store(tmp_path).record("evt-1", TRUE_POSITIVE, reviewer="robert").note == ""


@pytest.mark.parametrize(
    ("event_id", "verdict", "reviewer", "match"),
    [
        ("", TRUE_POSITIVE, "robert", "event_id"),
        ("   ", TRUE_POSITIVE, "robert", "event_id"),
        ("evt-1", "maybe", "robert", "verdict must be one of"),
        ("evt-1", "", "robert", "verdict must be one of"),
        ("evt-1", TRUE_POSITIVE, "", "reviewer"),
    ],
)
def test_malformed_verdicts_are_rejected(
    tmp_path: Path, event_id: str, verdict: str, reviewer: str, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        _store(tmp_path).record(event_id, verdict, reviewer=reviewer)


def test_a_long_note_is_truncated(tmp_path: Path) -> None:
    review = _store(tmp_path).record("e", FALSE_POSITIVE, reviewer="r", note="x" * 5000)
    assert len(review.note) == 2000


def test_the_parent_directory_is_created(tmp_path: Path) -> None:
    store = ReviewStore(tmp_path / "nested" / "deeper" / "reviews.jsonl")
    store.record("evt-1", TRUE_POSITIVE, reviewer="robert")
    assert store.path.exists()


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def test_a_missing_file_reads_as_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.reviews() == {}
    assert store.history() == []


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record("evt-1", TRUE_POSITIVE, reviewer="robert")
    with store.path.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
        handle.write("\n")
        handle.write('"bare string"\n')
        handle.write(json.dumps({"event_id": "", "verdict": TRUE_POSITIVE}) + "\n")
        handle.write(json.dumps({"event_id": "evt-2", "verdict": "nonsense"}) + "\n")

    assert list(store.reviews()) == ["evt-1"]
    assert len(store.history()) == 1


def test_a_review_missing_optional_fields_still_loads(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(
        json.dumps({"event_id": "evt-1", "verdict": TRUE_POSITIVE}) + "\n", encoding="utf-8"
    )
    assert store.reviews()["evt-1"].reviewer == "unknown"


# ---------------------------------------------------------------------------
# The criterion it exists to unblock
# ---------------------------------------------------------------------------


def _audit_with_hard_denies(tmp_path: Path, count: int) -> tuple[Path, list[str]]:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path), policy_fingerprint="sha256:test")
    for index in range(count):
        logger.log(
            actor="agent",
            action=f"rm -rf / #{index}",
            decision={
                "allowed": False,
                "risk_score": 171,
                "reason": "destructive system command",
                "state": "hard_deny",
            },
            context={},
        )
    ids = [json.loads(line)["event_id"] for line in path.read_text(encoding="utf-8").splitlines()]
    return path, ids


def _criterion(report: object) -> object:
    return next(c for c in report.criteria if c.name == "hard_deny_reviewed")  # type: ignore[attr-defined]


def test_reviewing_every_event_passes_the_criterion(tmp_path: Path) -> None:
    audit, ids = _audit_with_hard_denies(tmp_path, 3)
    store = _store(tmp_path)
    for event_id in ids:
        store.record(event_id, TRUE_POSITIVE, reviewer="robert")

    report = build_report(audit, min_decisions=1, min_days=0.0, review_path=store.path)
    criterion = _criterion(report)
    assert criterion.passed is True  # type: ignore[attr-defined]
    assert "robert" in criterion.detail  # type: ignore[attr-defined]


def test_one_unreviewed_event_holds_the_gate(tmp_path: Path) -> None:
    audit, ids = _audit_with_hard_denies(tmp_path, 3)
    store = _store(tmp_path)
    for event_id in ids[:2]:
        store.record(event_id, TRUE_POSITIVE, reviewer="robert")

    criterion = _criterion(
        build_report(audit, min_decisions=1, min_days=0.0, review_path=store.path)
    )
    assert criterion.passed is False  # type: ignore[attr-defined]
    assert "1 of 3" in criterion.detail  # type: ignore[attr-defined]


def test_a_false_positive_blocks_the_advance_even_when_all_are_reviewed(
    tmp_path: Path,
) -> None:
    """
    Enforcing a rule a human already called wrong is the exact outcome phase 1
    exists to prevent. Reviewing everything is not the same as approving it.
    """
    audit, ids = _audit_with_hard_denies(tmp_path, 3)
    store = _store(tmp_path)
    store.record(ids[0], TRUE_POSITIVE, reviewer="robert")
    store.record(ids[1], TRUE_POSITIVE, reviewer="robert")
    store.record(ids[2], FALSE_POSITIVE, reviewer="robert", note="scoped cleanup, not root")

    criterion = _criterion(
        build_report(audit, min_decisions=1, min_days=0.0, review_path=store.path)
    )
    assert criterion.passed is False  # type: ignore[attr-defined]
    assert "FALSE" in criterion.detail  # type: ignore[attr-defined]
    assert "restart the window" in criterion.detail  # type: ignore[attr-defined]


def test_events_beyond_the_sample_cap_cannot_be_reviewed_away(tmp_path: Path) -> None:
    """
    The report only samples N hard_deny events. Reviewing the sampled ones must
    not pass a gate covering events nobody was ever shown.
    """
    audit, ids = _audit_with_hard_denies(tmp_path, 6)
    store = _store(tmp_path)
    for event_id in ids[:2]:
        store.record(event_id, TRUE_POSITIVE, reviewer="robert")

    criterion = _criterion(
        build_report(
            audit,
            min_decisions=1,
            min_days=0.0,
            review_path=store.path,
            max_hard_deny_samples=2,
        )
    )
    assert criterion.passed is False  # type: ignore[attr-defined]
    assert "4 of 6" in criterion.detail  # type: ignore[attr-defined]


def test_reviews_reach_the_report_events(tmp_path: Path) -> None:
    audit, ids = _audit_with_hard_denies(tmp_path, 2)
    store = _store(tmp_path)
    store.record(ids[0], TRUE_POSITIVE, reviewer="robert", note="genuinely destructive")

    events = build_report(audit, review_path=store.path).hard_deny_events
    assert events[0]["review"]["verdict"] == TRUE_POSITIVE
    assert events[0]["review"]["note"] == "genuinely destructive"
    assert events[1]["review"] is None
    assert all(e["event_id"] for e in events)


def test_without_a_review_path_nothing_is_reviewed(tmp_path: Path) -> None:
    """Back-compat: callers that never opted in behave exactly as before."""
    audit, _ = _audit_with_hard_denies(tmp_path, 2)
    report = build_report(audit, min_decisions=1, min_days=0.0)
    assert _criterion(report).passed is False  # type: ignore[attr-defined]
    assert all(e["review"] is None for e in report.hard_deny_events)
