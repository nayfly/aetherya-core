from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from aetherya.audit import AuditLogger
from aetherya.policy_replay import main, replay

_POLICY = "config/policy.yaml"


def _candidate(tmp_path: Path, mutate: Callable[[str], str]) -> Path:
    """A policy file with one edit applied to the repo default."""
    source = Path(_POLICY).read_text(encoding="utf-8")
    path = tmp_path / "candidate.yaml"
    path.write_text(mutate(source), encoding="utf-8")
    return path


def _trail(tmp_path: Path, rows: list[tuple[str, str, list[str]]]) -> Path:
    """rows: (tool, raw_input, parameter_names)."""
    path = tmp_path / "decisions.jsonl"
    logger = AuditLogger(str(path))
    for tool, raw_input, params in rows:
        logger.log(
            actor="robert",
            action=raw_input,
            decision={"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
            context={
                "action": {
                    "intent": "operate",
                    "tool": tool,
                    "target": None,
                    "operation": None,
                    "parameter_names": params,
                }
            },
        )
    return path


# ---------------------------------------------------------------------------
# The question a replay answers
# ---------------------------------------------------------------------------


def test_an_identical_candidate_changes_nothing(tmp_path: Path) -> None:
    """The null case has to be null, or every real diff is noise."""
    trail = _trail(tmp_path, [("exec", "exec ls -la", ["command"])] * 3)
    report = replay(
        baseline_path=_POLICY, candidate_path=_POLICY, audit_path=trail, check_corpus=False
    )

    assert report.total == 3
    assert report.unchanged == 3
    assert report.changes == []


def test_a_candidate_that_narrows_the_vocabulary_shows_as_tightened(tmp_path: Path) -> None:
    """
    Dropping `read` from the alias map is the state the policy was in two days
    ago, when every call was refused for speaking an unknown name.
    """
    candidate = _candidate(tmp_path, lambda s: s.replace("  read: filesystem\n", "", 1))
    trail = _trail(
        tmp_path,
        [("read", "read notes.md", ["path"]), ("exec", "exec ls", ["command"])],
    )
    report = replay(
        baseline_path=_POLICY, candidate_path=candidate, audit_path=trail, check_corpus=False
    )

    assert len(report.tightened) == 1
    assert report.tightened[0].before == "log_only"
    assert report.tightened[0].after == "hard_deny"
    assert report.loosened == []


def test_a_candidate_that_stops_refusing_an_attack_is_a_regression(tmp_path: Path) -> None:
    """
    The failure this exists to catch: someone comments out a rule family because
    it produced false positives, and the corpus stops being refused.
    """
    candidate = _candidate(
        tmp_path, lambda s: s.replace('    - "rm -rf /"', '    # - "rm -rf /"', 1)
    )
    report = replay(baseline_path=_POLICY, candidate_path=candidate, audit_path=None)

    assert report.corpus_checked > 0
    assert report.corpus_regressions
    assert report.safe_to_promote is False


def test_the_repo_policy_has_no_regression_against_its_own_corpus() -> None:
    """Guards the guard: a checker that fires on the shipped policy is broken."""
    report = replay(baseline_path=_POLICY, candidate_path=_POLICY, audit_path=None)

    assert report.corpus_checked > 0
    assert report.corpus_regressions == []
    assert report.safe_to_promote is True


def test_tightening_alone_is_still_safe_to_promote(tmp_path: Path) -> None:
    """
    A stricter decision is friction, not a fault. Gating on it would make every
    improvement fail the check that is supposed to enable improvements.
    """
    candidate = _candidate(tmp_path, lambda s: s.replace("  read: filesystem\n", "", 1))
    trail = _trail(tmp_path, [("read", "read notes.md", ["path"])])
    report = replay(baseline_path=_POLICY, candidate_path=candidate, audit_path=trail)

    assert report.tightened
    assert report.safe_to_promote is True


# ---------------------------------------------------------------------------
# Reading the trail
# ---------------------------------------------------------------------------


def test_events_without_a_structured_action_are_not_replayed(tmp_path: Path) -> None:
    """
    Decisions recorded before the trail carried structure cannot be replayed.
    Counting them as unchanged would overstate how much of the window was
    actually covered.
    """
    path = tmp_path / "decisions.jsonl"
    AuditLogger(str(path)).log(
        actor="robert",
        action="legacy event",
        decision={"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
        context={},
    )
    report = replay(
        baseline_path=_POLICY, candidate_path=_POLICY, audit_path=path, check_corpus=False
    )
    assert report.total == 0


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    trail = _trail(tmp_path, [("exec", "exec ls", ["command"])])
    with trail.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
        handle.write("\n")
        handle.write('"bare string"\n')

    report = replay(
        baseline_path=_POLICY, candidate_path=_POLICY, audit_path=trail, check_corpus=False
    )
    assert report.total == 1


def test_a_missing_trail_still_checks_the_corpus(tmp_path: Path) -> None:
    """A policy can be replayed before any traffic exists."""
    report = replay(
        baseline_path=_POLICY, candidate_path=_POLICY, audit_path=tmp_path / "nope.jsonl"
    )
    assert report.total == 0
    assert report.corpus_checked > 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_the_exit_code_reacts_to_regressions_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = _candidate(
        tmp_path, lambda s: s.replace('    - "rm -rf /"', '    # - "rm -rf /"', 1)
    )
    assert main(["--candidate", str(candidate), "--audit-path", str(tmp_path / "none.jsonl")]) == 1
    assert "DO NOT PROMOTE" in capsys.readouterr().out

    assert main(["--candidate", _POLICY, "--audit-path", str(tmp_path / "none.jsonl")]) == 0
    assert "SAFE TO PROMOTE" in capsys.readouterr().out


def test_json_output_carries_the_verdict_and_the_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = _candidate(tmp_path, lambda s: s.replace("  read: filesystem\n", "", 1))
    trail = _trail(tmp_path, [("read", "read notes.md", ["path"])])

    main(["--candidate", str(candidate), "--audit-path", str(trail), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["safe_to_promote"] is True
    assert payload["traffic"]["tightened"] == 1
    assert payload["changes"][0]["loosened"] is False


def test_a_malformed_candidate_fails_with_a_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "broken.yaml"
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    del data["aggregator"]["hard_deny_if"]
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    assert main(["--candidate", str(path)]) == 2
    assert "error:" in capsys.readouterr().err


def test_skipping_the_corpus_is_reported_as_such(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without the corpus the exit code means nothing; the flag says so."""
    assert main(["--candidate", _POLICY, "--no-corpus", "--audit-path", str(tmp_path / "x")]) == 0
    assert "0 cases" in capsys.readouterr().out


def test_the_text_report_names_what_moved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = _candidate(tmp_path, lambda s: s.replace("  read: filesystem\n", "", 1))
    trail = _trail(tmp_path, [("read", "read notes.md", ["path"])])

    main(["--candidate", str(candidate), "--audit-path", str(trail)])
    out = capsys.readouterr().out
    assert "tightened (1)" in out
    assert "read notes.md" in out


def test_an_empty_trail_reports_that_nothing_was_replayed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Silence would read as "no changes" when it means "nothing measured"."""
    path = tmp_path / "decisions.jsonl"
    path.write_text("", encoding="utf-8")

    main(["--candidate", _POLICY, "--audit-path", str(path)])
    assert "none replayed" in capsys.readouterr().out


def test_a_missing_corpus_file_is_not_a_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A checkout without fixtures reports zero cases, not zero refusals."""
    import aetherya.policy_replay as module

    monkeypatch.setattr(module, "_CORPUS_DIR", tmp_path / "absent")
    report = replay(baseline_path=_POLICY, candidate_path=_POLICY, audit_path=None)

    assert report.corpus_checked == 0
    assert report.safe_to_promote is True


def test_a_long_change_list_is_truncated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A diff of 200 rows in a terminal is not a report anyone reads."""
    candidate = _candidate(tmp_path, lambda s: s.replace("  read: filesystem\n", "", 1))
    trail = _trail(tmp_path, [("read", f"read file{i}.md", ["path"]) for i in range(15)])

    main(["--candidate", str(candidate), "--audit-path", str(trail)])
    out = capsys.readouterr().out
    assert "tightened (15)" in out
    assert "and 3 more" in out


def test_a_loosened_decision_is_called_out_before_promotion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    No adversarial regression is not the same as no risk. A decision that got
    less strict on real traffic is where one hides, so the verdict names it.
    """
    # Baseline without `read`; candidate is the shipped policy, which has it.
    baseline = _candidate(tmp_path, lambda s: s.replace("  read: filesystem\n", "", 1))
    trail = _trail(tmp_path, [("read", "read notes.md", ["path"])])

    report = replay(baseline_path=baseline, candidate_path=_POLICY, audit_path=trail)
    assert report.loosened
    assert report.safe_to_promote is True

    main(
        [
            "--baseline",
            str(baseline),
            "--candidate",
            _POLICY,
            "--audit-path",
            str(trail),
        ]
    )
    out = capsys.readouterr().out
    assert "loosened (1)" in out
    assert "Read the 1 loosened decision(s)" in out


def test_benign_corpus_entries_are_not_counted_as_attacks() -> None:
    """
    The evasion corpus carries a few cases the engine is expected to allow.
    Counting them would inflate `corpus_checked` and, worse, report a regression
    the first time one of them is correctly permitted.
    """
    import json as _json

    from aetherya.policy_replay import _CORPUS_DIR

    cases = _json.loads((_CORPUS_DIR / "procedural_evasions.json").read_text(encoding="utf-8"))[
        "cases"
    ]
    blocked = [c for c in cases if (c.get("expected") or {}).get("blocked")]

    report = replay(baseline_path=_POLICY, candidate_path=_POLICY, audit_path=None)
    assert report.corpus_checked == len(blocked)


def test_identical_state_totals_are_not_printed_twice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The before/after block is noise when the distribution did not move."""
    trail = _trail(tmp_path, [("exec", "exec ls", ["command"])])
    main(["--candidate", _POLICY, "--audit-path", str(trail)])

    out = capsys.readouterr().out
    assert "unchanged          1" in out
    assert "before  {" not in out


def test_a_corpus_case_expected_to_pass_is_not_treated_as_an_attack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Every case in the shipped corpus expects a refusal, so this branch is not
    reachable today. It exists because the format allows `blocked: false`, and
    without it the first permitted case added would be counted as an attack and
    reported as a regression the moment the engine correctly allows it.
    """
    import aetherya.policy_replay as module

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "procedural_evasions.json").write_text(
        json.dumps(
            {
                "version": "v1",
                "kind": "procedural_evasions",
                "cases": [
                    {
                        "id": "expected_refused",
                        "category": "x",
                        "text": "rm -rf /",
                        "expected": {"blocked": True, "hard_deny": True},
                    },
                    {
                        "id": "expected_allowed",
                        "category": "x",
                        "text": "list the files in this directory",
                        "expected": {"blocked": False, "hard_deny": False},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "_CORPUS_DIR", corpus)

    report = replay(baseline_path=_POLICY, candidate_path=_POLICY, audit_path=None)
    assert report.corpus_checked == 1
    assert report.corpus_regressions == []
