from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aetherya.audit import AuditLogger
from aetherya.rollout_report import build_report, main


def _audit(tmp_path: Path, rows: list[tuple[str, str, str]]) -> Path:
    """rows: (actor, state, reason). Written through AuditLogger so the chain is real."""
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path), policy_fingerprint="sha256:test-policy")
    for actor, state, reason in rows:
        logger.log(
            actor=actor,
            action=f"{state} action for {actor}",
            decision={
                "allowed": state in {"allow", "log_only"},
                "risk_score": 100 if state == "hard_deny" else 0,
                "reason": reason,
                "state": state,
            },
            context={"mode": "operative", "action": {"tool": "shell"}},
        )
    return path


def test_counts_decisions_by_state(tmp_path: Path) -> None:
    path = _audit(
        tmp_path,
        [
            ("a", "allow", "ok"),
            ("a", "allow", "ok"),
            ("b", "hard_deny", "destructive system command"),
            ("c", "escalate", "confirmation missing"),
        ],
    )
    report = build_report(path)

    assert report.total_decisions == 4
    assert report.states == {"allow": 2, "escalate": 1, "hard_deny": 1}
    assert report.actors_by_state["allow"] == ["a"]


def test_reports_what_the_next_phase_would_act_on(tmp_path: Path) -> None:
    """The number phase 1 exists to produce."""
    path = _audit(
        tmp_path,
        [("a", "allow", "ok"), ("b", "hard_deny", "bad"), ("c", "escalate", "hold")],
    )

    # Phase 2 only enforces hard_deny.
    assert build_report(path, current_phase=1).would_block_next_phase == 1
    # Phase 3 adds deny and escalate, so it also acts on the escalation.
    assert build_report(path, current_phase=2).would_block_next_phase == 2


def test_lists_hard_deny_events_for_manual_review(tmp_path: Path) -> None:
    path = _audit(
        tmp_path,
        [("bot", "hard_deny", "destructive system command"), ("bot", "allow", "ok")],
    )
    report = build_report(path)

    assert len(report.hard_deny_events) == 1
    event = report.hard_deny_events[0]
    assert event["actor"] == "bot"
    assert "destructive" in event["reason"]


def test_hard_deny_sample_is_bounded(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("bot", "hard_deny", "bad")] * 20)
    assert len(build_report(path, max_hard_deny_samples=5).hard_deny_events) == 5


def test_hard_deny_review_never_auto_passes(tmp_path: Path) -> None:
    """
    The tool can count and list these; it cannot judge them. Auto-passing would
    turn the phase gate into a formality, which is exactly the failure mode the
    criterion exists to prevent.
    """
    path = _audit(tmp_path, [("a", "allow", "ok")] * 3)
    report = build_report(path, min_decisions=1, min_days=0.0)

    reviewed = next(c for c in report.criteria if c.name == "hard_deny_reviewed")
    assert reviewed.passed is False
    assert report.ready_to_advance is False


def test_insufficient_window_fails_the_criterion(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")] * 3)
    report = build_report(path, min_decisions=10_000, min_days=14.0)

    window = next(c for c in report.criteria if c.name == "sufficient_window")
    assert window.passed is False
    assert "3 decisions" in window.detail


def test_enough_decisions_satisfies_the_window(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")] * 5)
    report = build_report(path, min_decisions=5, min_days=999.0)
    assert next(c for c in report.criteria if c.name == "sufficient_window").passed is True


def test_mixed_policy_fingerprints_fail_the_criterion(tmp_path: Path) -> None:
    """
    Two fingerprints means the window mixes different engines: the measurement
    describes no single policy and has to be restarted.
    """
    path = tmp_path / "decisions.jsonl"
    for fingerprint in ("sha256:one", "sha256:two"):
        logger = AuditLogger(str(path), policy_fingerprint=fingerprint)
        logger.log(
            actor="a",
            action="x",
            decision={"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
            context={},
        )

    report = build_report(path)
    assert len(report.policy_fingerprints) == 2
    assert next(c for c in report.criteria if c.name == "single_policy").passed is False


def test_a_tampered_chain_fails_the_criterion(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok"), ("b", "allow", "ok")])
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    events[0]["actor"] = "tampered"
    path.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8"
    )

    report = build_report(path)
    assert report.chain_valid is False
    assert next(c for c in report.criteria if c.name == "chain_intact").passed is False


def test_counts_escalations_and_skipped_semantics(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path))
    logger.log(
        actor="a",
        action="x",
        decision={"allowed": False, "risk_score": 50, "reason": "r", "state": "escalate"},
        context={
            "intent_escalation": {"escalated": True},
            "constitution": {"semantic_skipped": "model_not_warm"},
        },
    )
    report = build_report(path)

    assert report.intent_escalations == 1
    assert report.semantic_skipped == 1


def test_window_days_spans_first_to_last_event(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    base = datetime.now(UTC)
    rows = []
    for offset in (0, 10):
        rows.append(
            {
                "ts": (base + timedelta(days=offset)).isoformat(),
                "actor": "a",
                "action": "x",
                "decision": {"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
                "context": {},
            }
        )
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    report = build_report(path)
    assert 9.9 < report.window_days < 10.1


def test_malformed_and_blank_lines_are_skipped(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")])
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n")
        handle.write("not json at all\n")
        handle.write('"a bare string"\n')

    report = build_report(path)
    assert report.total_decisions == 1
    # A malformed line is a finding, not something to swallow silently.
    assert report.chain_valid is False
    assert "invalid JSON" in str(report.chain_error_detail)


def test_events_without_a_timestamp_do_not_break_the_window(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text(
        json.dumps(
            {
                "actor": "a",
                "action": "x",
                "ts": "not-a-timestamp",
                "decision": {"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
                "context": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    report = build_report(path)
    assert report.window_days == 0.0
    assert report.first_event is None


def test_missing_audit_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="audit file not found"):
        build_report(tmp_path / "nope.jsonl")


def test_report_serializes(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("a", "hard_deny", "bad")])
    payload = build_report(path).to_dict()

    assert payload["current_phase"] == 1
    assert payload["next_phase"] == 2
    assert payload["ready_to_advance"] is False
    assert payload["chain"]["valid"] is True


def test_next_phase_is_clamped_at_the_last_one(tmp_path: Path) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")])
    assert build_report(path, current_phase=3).to_dict()["next_phase"] == 3


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_exits_nonzero_when_not_ready(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Usable as a gate in a promotion pipeline."""
    path = _audit(tmp_path, [("a", "hard_deny", "bad")])
    assert main(["--audit-path", str(path), "--json"]) == 1

    payload = json.loads(capsys.readouterr().out)
    assert payload["ready_to_advance"] is False


def test_cli_text_output_lists_events_and_criteria(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _audit(tmp_path, [("bot", "hard_deny", "destructive system command")])
    main(["--audit-path", str(path)])

    out = capsys.readouterr().out
    assert "ROLLOUT REPORT" in out
    assert "hard_deny events to review" in out
    assert "NOT READY" in out


def test_cli_reports_a_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--audit-path", str(tmp_path / "nope.jsonl")]) == 2
    assert "audit file not found" in capsys.readouterr().err


def test_cli_accepts_a_phase(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")])
    main(["--audit-path", str(path), "--phase", "2", "--json"])
    assert json.loads(capsys.readouterr().out)["current_phase"] == 2


def test_cli_is_reachable_through_the_main_entry_point(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from aetherya.cli import main as cli_main

    path = _audit(tmp_path, [("a", "allow", "ok")])
    cli_main(["rollout", "report", "--audit-path", str(path), "--json"])
    assert "ready_to_advance" in capsys.readouterr().out


def test_empty_audit_file_produces_an_empty_report(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    path.write_text("", encoding="utf-8")

    report = build_report(path)
    assert report.total_decisions == 0
    assert report.states == {}
    assert report.ready_to_advance is False
    assert report.chain_valid is False


def test_text_output_without_hard_denies_omits_the_review_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")])
    main(["--audit-path", str(path)])
    assert "hard_deny events to review" not in capsys.readouterr().out


def test_actions_are_truncated_in_the_review_list(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    AuditLogger(str(path)).log(
        actor="a",
        action="x" * 400,
        decision={"allowed": False, "risk_score": 100, "reason": "bad", "state": "hard_deny"},
        context={},
    )
    assert len(build_report(path).hard_deny_events[0]["action"]) <= 160


def test_context_without_an_action_block_is_tolerated(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    AuditLogger(str(path)).log(
        actor="a",
        action="x",
        decision={"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
        context={"action": "not-a-mapping"},
    )
    assert build_report(path).tools_by_state["allow"] == ["-"]


def test_json_output_is_machine_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _audit(tmp_path, [("a", "allow", "ok")] * 2)
    main(["--audit-path", str(path), "--json", "--min-decisions", "1", "--min-days", "0"])

    payload: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert payload["window"]["total_decisions"] == 2
    assert isinstance(payload["criteria"], list)
