from __future__ import annotations

import json
from pathlib import Path

from aetherya.audit import AuditLogger


class Marker:
    pass


def read_events(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def test_audit_logger_decision_id_is_deterministic_for_same_payload(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)

    decision = {"allowed": True, "risk_score": 0, "confidence": 0.75, "state": "allow"}
    context = {"mode": "consultive", "signals": [{"source": "constitution", "score": 0}]}

    ev1 = logger.log(actor="robert", action="help user", decision=decision, context=context)
    ev2 = logger.log(actor="robert", action="help user", decision=decision, context=context)

    assert ev1.event_id != ev2.event_id
    assert ev1.context_hash == ev2.context_hash
    assert ev1.decision_id == ev2.decision_id
    assert ev1.context_hash.startswith("sha256:")
    assert ev1.decision_id.startswith("sha256:")

    events = read_events(path)
    assert len(events) == 2
    assert events[0]["decision_id"] == ev1.decision_id
    assert events[0]["context_hash"] == ev1.context_hash


def test_audit_logger_hashes_change_when_context_changes(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)

    decision = {"allowed": False, "risk_score": 75, "state": "escalate"}

    ev1 = logger.log(
        actor="robert",
        action="run dangerous op",
        decision=decision,
        context={"mode": "operative", "stage": "execution_gate"},
    )
    ev2 = logger.log(
        actor="robert",
        action="run dangerous op",
        decision=decision,
        context={"mode": "operative", "stage": "confirmation_gate"},
    )

    assert ev1.context_hash != ev2.context_hash
    assert ev1.decision_id != ev2.decision_id


def test_audit_logger_normalizes_non_json_values(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)

    event = logger.log(
        actor="robert",
        action="inspect",
        decision={"allowed": True, "meta": {"tags": {"b", "a"}}},
        context={
            "set_values": {"y", "x"},
            "tuple_values": (1, 2, 3),
            "nan_value": float("nan"),
            "obj": Marker(),
        },
    )

    assert event.context["set_values"] == ["x", "y"]
    assert event.context["tuple_values"] == [1, 2, 3]
    assert event.context["nan_value"] == "nan"
    assert isinstance(event.context["obj"], str)
    assert event.decision["meta"]["tags"] == ["a", "b"]

    events = read_events(path)
    assert events[0]["context"]["set_values"] == ["x", "y"]


def test_audit_logger_wraps_non_dict_payloads(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)

    event = logger.log(  # type: ignore[arg-type]
        actor="robert",
        action="coerce",
        decision=["deny", "hard_deny"],
        context=("operative", "stage"),
    )

    assert event.decision == {"value": ["deny", "hard_deny"]}
    assert event.context == {"value": ["operative", "stage"]}
