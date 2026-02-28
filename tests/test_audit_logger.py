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


def test_audit_logger_injects_default_policy_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, policy_fingerprint="sha256:abc123")

    event = logger.log(
        actor="robert",
        action="inspect",
        decision={"allowed": True},
        context={"mode": "consultive"},
    )

    assert event.policy_fingerprint == "sha256:abc123"
    assert event.context["policy_fingerprint"] == "sha256:abc123"

    events = read_events(path)
    assert events[0]["policy_fingerprint"] == "sha256:abc123"


def test_audit_logger_call_level_policy_fingerprint_overrides_default(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, policy_fingerprint="sha256:old")

    event = logger.log(
        actor="robert",
        action="inspect",
        decision={"allowed": True},
        context={"mode": "consultive"},
        policy_fingerprint="sha256:new",
    )

    assert event.policy_fingerprint == "sha256:new"
    assert event.context["policy_fingerprint"] == "sha256:new"


def test_audit_logger_attestation_is_deterministic_without_key(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)

    decision = {"allowed": True, "risk_score": 0, "state": "allow"}
    context = {"mode": "consultive"}

    ev1 = logger.log(actor="robert", action="help user", decision=decision, context=context)
    ev2 = logger.log(actor="robert", action="help user", decision=decision, context=context)

    assert ev1.attestation_alg == "sha256"
    assert ev1.attestation.startswith("sha256:")
    assert ev1.attestation == ev2.attestation


def test_audit_logger_attestation_uses_hmac_when_key_provided(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="super-secret")

    event = logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert event.attestation_alg == "hmac-sha256"
    assert event.attestation.startswith("hmac-sha256:")


def test_audit_logger_set_attestation_key_changes_signature(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path)

    base = logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    logger.set_attestation_key("new-key")
    signed = logger.log(
        actor="robert",
        action="help user",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert base.attestation_alg == "sha256"
    assert signed.attestation_alg == "hmac-sha256"
    assert base.attestation != signed.attestation


def test_audit_logger_chain_hash_links_events(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")

    ev1 = logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    ev2 = logger.log(
        actor="robert",
        action="two",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert ev1.prev_chain_hash is None
    assert ev1.chain_hash.startswith("sha256:")
    assert ev2.prev_chain_hash == ev1.chain_hash
    assert ev2.chain_hash.startswith("sha256:")
    assert ev2.chain_hash != ev1.chain_hash


def test_audit_logger_bootstraps_chain_tip_when_reopened(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    first_logger = AuditLogger(path, attestation_key="secret")
    first = first_logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    second_logger = AuditLogger(path, attestation_key="secret")
    second = second_logger.log(
        actor="robert",
        action="two",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert second.prev_chain_hash == first.chain_hash


def test_audit_logger_chain_tip_skips_blank_trailing_lines(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(path, attestation_key="secret")
    first = logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )
    path.write_text(path.read_text(encoding="utf-8") + "\n\n", encoding="utf-8")

    reopened = AuditLogger(path, attestation_key="secret")
    second = reopened.log(
        actor="robert",
        action="two",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert second.prev_chain_hash == first.chain_hash


def test_audit_logger_chain_tip_invalid_json_falls_back_to_none(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("{invalid json}\n", encoding="utf-8")

    logger = AuditLogger(path, attestation_key="secret")
    event = logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert event.prev_chain_hash is None


def test_audit_logger_chain_tip_non_object_json_falls_back_to_none(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("[1,2,3]\n", encoding="utf-8")

    logger = AuditLogger(path, attestation_key="secret")
    event = logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert event.prev_chain_hash is None


def test_audit_logger_chain_tip_blank_file_falls_back_to_none(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("\n\n", encoding="utf-8")

    logger = AuditLogger(path, attestation_key="secret")
    event = logger.log(
        actor="robert",
        action="one",
        decision={"allowed": True, "risk_score": 0, "state": "allow"},
        context={"mode": "consultive"},
    )

    assert event.prev_chain_hash is None
