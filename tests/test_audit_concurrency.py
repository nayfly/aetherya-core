from __future__ import annotations

import json
import threading
from pathlib import Path

from aetherya.audit import AuditLogger, _tail_chain_tip
from aetherya.audit_verify import verify_audit_file

# ---------------------------------------------------------------------------
# A hash chain is a sequence, so two writers appending to one file is a
# correctness problem, not a performance one. Before the lock, five of six
# events failed verification and nothing surfaced until `audit verify` ran:
# both writers believed they had succeeded.
#
# flock is per open file description, so separate AuditLogger instances contend
# with each other inside one process exactly as they do across processes. That
# makes this testable without spawning anything.
# ---------------------------------------------------------------------------

DECISION = {"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"}


def _verify(path: Path) -> tuple[int, int]:
    """Returns (total events, invalid events)."""
    results = verify_audit_file(str(path), require_chain=True)
    return len(results), sum(1 for r in results if not r.verification.valid)


def test_two_writers_keep_the_chain_intact(tmp_path: Path) -> None:
    """The case that motivated the lock: a container and a gateway, one volume."""
    path = tmp_path / "decisions.jsonl"
    container = AuditLogger(str(path), policy_fingerprint="sha256:x")
    gateway = AuditLogger(str(path), policy_fingerprint="sha256:x")

    for index in range(5):
        container.log(actor="container", action=f"A{index}", decision=DECISION, context={})
        gateway.log(actor="gateway", action=f"B{index}", decision=DECISION, context={})

    total, invalid = _verify(path)
    assert total == 10
    assert invalid == 0


def test_the_chain_survives_concurrent_writers(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    writers = [AuditLogger(str(path), policy_fingerprint="sha256:x") for _ in range(4)]

    def hammer(logger: AuditLogger, name: str) -> None:
        for index in range(15):
            logger.log(actor=name, action=f"{name}-{index}", decision=DECISION, context={})

    threads = [
        threading.Thread(target=hammer, args=(logger, f"w{position}"))
        for position, logger in enumerate(writers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    total, invalid = _verify(path)
    assert total == 60
    assert invalid == 0


def test_every_event_is_written_exactly_once(tmp_path: Path) -> None:
    """A lock that serialised writes but dropped one would still verify clean."""
    path = tmp_path / "decisions.jsonl"
    writers = [AuditLogger(str(path)) for _ in range(3)]

    def hammer(logger: AuditLogger, name: str) -> None:
        for index in range(10):
            logger.log(actor=name, action=f"{name}-{index}", decision=DECISION, context={})

    threads = [
        threading.Thread(target=hammer, args=(logger, f"w{position}"))
        for position, logger in enumerate(writers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    actions = [json.loads(line)["action"] for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(actions) == 30
    assert len(set(actions)) == 30


def test_a_second_writer_is_noticed_without_reading_the_whole_file(tmp_path: Path) -> None:
    """
    The stale-tip check is a stat(), not a re-read. Re-reading per write would
    be O(file) and turn the audit log into the slowest stage in the pipeline.
    """
    path = tmp_path / "decisions.jsonl"
    first = AuditLogger(str(path))
    second = AuditLogger(str(path))

    first.log(actor="a", action="one", decision=DECISION, context={})
    # `second` still believes the file is empty until it looks.
    assert second._known_size == 0  # noqa: SLF001
    second.log(actor="b", action="two", decision=DECISION, context={})

    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert events[1]["prev_chain_hash"] == events[0]["chain_hash"]
    assert _verify(path)[1] == 0


# ---------------------------------------------------------------------------
# Tail reader
# ---------------------------------------------------------------------------


def test_the_tail_reader_agrees_with_the_last_event(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path))
    for index in range(20):
        logger.log(actor="a", action=f"e{index}", decision=DECISION, context={})

    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert _tail_chain_tip(path) == last["chain_hash"]


def test_the_tail_reader_grows_its_window_past_a_long_event(tmp_path: Path) -> None:
    """
    A single event can exceed the window — a large context, a long command. If
    the window never grew, the tip would read as None and the next event would
    silently start a second chain in the same file.
    """
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path))
    logger.log(actor="a", action="x" * 5_000, decision=DECISION, context={"blob": "y" * 40_000})

    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert _tail_chain_tip(path, window=256) == last["chain_hash"]


def test_the_tail_reader_ignores_a_partial_leading_line(tmp_path: Path) -> None:
    """A window that opens mid-record must not parse the fragment as an event."""
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path))
    for index in range(6):
        logger.log(actor="a", action=f"e{index}", decision=DECISION, context={})

    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    for window in (64, 128, 512, 4096):
        assert _tail_chain_tip(path, window=window) == last["chain_hash"]


def test_the_tail_reader_handles_an_empty_or_missing_file(tmp_path: Path) -> None:
    assert _tail_chain_tip(tmp_path / "nope.jsonl") is None
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert _tail_chain_tip(empty) is None


def test_the_tail_reader_rejects_a_malformed_last_line(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text('{"chain_hash": "abc"}\nnot json\n', encoding="utf-8")
    assert _tail_chain_tip(path) is None


def test_the_tail_reader_rejects_a_non_object_last_line(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text('{"chain_hash": "abc"}\n"bare string"\n', encoding="utf-8")
    assert _tail_chain_tip(path) is None


def test_the_tail_reader_treats_a_missing_chain_hash_as_no_tip(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text('{"actor": "a"}\n', encoding="utf-8")
    assert _tail_chain_tip(path) is None

    blank = tmp_path / "blank.jsonl"
    blank.write_text('{"chain_hash": "   "}\n', encoding="utf-8")
    assert _tail_chain_tip(blank) is None


def test_the_lock_file_sits_beside_the_trail(tmp_path: Path) -> None:
    """
    Locking a sidecar rather than the JSONL keeps readers out of the way of
    writers: `audit verify` and the console never contend with a decision.
    """
    path = tmp_path / "decisions.jsonl"
    AuditLogger(str(path)).log(actor="a", action="one", decision=DECISION, context={})
    assert (tmp_path / "decisions.jsonl.lock").exists()


def test_the_lock_directory_is_created_for_a_nested_path(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "deeper" / "decisions.jsonl"
    AuditLogger(str(path)).log(actor="a", action="one", decision=DECISION, context={})
    assert path.exists()
    assert _verify(path)[1] == 0


def test_the_tail_reader_gives_up_when_the_whole_file_has_no_record(tmp_path: Path) -> None:
    """
    A file of only blank lines has no tip. Growing the window forever looking
    for one would hang on a corrupt trail.
    """
    path = tmp_path / "decisions.jsonl"
    path.write_text("\n\n\n\n", encoding="utf-8")
    assert _tail_chain_tip(path, window=2) is None
