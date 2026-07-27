from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_EXAMPLE = Path(__file__).parent.parent / "examples" / "agent_loop.py"


def _load_module() -> Any:
    """Examples are not an installed package; load the file directly."""
    spec = importlib.util.spec_from_file_location("agent_loop_example", _EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_loop_example"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def agent_loop() -> Any:
    return _load_module()


def _summary(agent_loop: Any, capsys: pytest.CaptureFixture[str], *args: str) -> dict[str, Any]:
    assert agent_loop.main(["--json", *args]) == 0
    return json.loads(capsys.readouterr().out)["summary"]


# ---------------------------------------------------------------------------
# The example is documentation that runs — it must keep running.
# ---------------------------------------------------------------------------


def test_phase_1_executes_everything_but_records_the_gap(
    agent_loop: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Shadow mode must not change behaviour, only measure it."""
    summary = _summary(agent_loop, capsys, "--phase", "1")

    assert summary["blocked"] == 0
    assert summary["executed"] == summary["total_actions"]
    # The number shadow mode exists to produce.
    assert summary["would_block_in_a_later_phase"] >= 1


def test_phase_2_refuses_the_injected_destructive_command(
    agent_loop: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert agent_loop.main(["--json", "--phase", "2"]) == 0
    payload = json.loads(capsys.readouterr().out)

    refused = [d for d in payload["decisions"] if not d["executed"]]
    assert len(refused) == 1
    assert refused[0]["tool"] == "run_shell"
    assert refused[0]["state"] == "hard_deny"


def test_phase_3_holds_escalations_for_a_human(
    agent_loop: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert agent_loop.main(["--json", "--phase", "3"]) == 0
    payload = json.loads(capsys.readouterr().out)

    held = [d for d in payload["decisions"] if d["label"] == "AWAITING APPROVAL"]
    assert held and all(d["state"] == "escalate" for d in held)
    assert payload["summary"]["would_block_in_a_later_phase"] == 0


def test_phase_3_executes_once_a_human_approves(
    agent_loop: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = _summary(agent_loop, capsys, "--phase", "3", "--approve")
    assert summary["executed"] > _summary(agent_loop, capsys, "--phase", "3")["executed"]


def test_enforcement_tightens_monotonically_across_phases(
    agent_loop: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each phase must refuse at least as much as the one before it."""
    blocked = [_summary(agent_loop, capsys, "--phase", str(p))["blocked"] for p in (1, 2, 3)]
    assert blocked == sorted(blocked)
    assert blocked[0] == 0


def test_the_prompt_injection_arrives_through_tool_output(agent_loop: Any) -> None:
    """
    The scenario is only meaningful if the model is not the attacker: the
    injection must come from data the agent read, not from its own instructions.
    """
    assert "IGNORE PREVIOUS INSTRUCTIONS" in agent_loop.POISONED_FILE
    assert "IGNORE PREVIOUS INSTRUCTIONS" in agent_loop.execute(
        "read_file", {"path": "/srv/app/deploy_notes.md"}
    )
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in agent_loop.execute(
        "read_file", {"path": "/srv/app/config.yaml"}
    )


def test_scripted_agent_only_proposes_the_destructive_call_after_reading_the_injection(
    agent_loop: Any,
) -> None:
    clean = agent_loop.ScriptedAgent()
    clean.propose([])
    clean.propose([{"role": "tool", "content": "nothing unusual"}])
    third = clean.propose([{"role": "tool", "content": "nothing unusual"}])

    # Without the injection the agent never reaches for the shell.
    assert third is None or third.tool != "run_shell"


def test_tool_calls_map_to_structured_actions(agent_loop: Any) -> None:
    """No free-text parsing in the trust path: the agent declares its action."""
    action = agent_loop.to_action("run_shell", {"command": "ls -la"})
    assert action.tool == "shell"
    assert action.intent == "operate"
    assert action.parameters["command"] == "ls -la"

    write = agent_loop.to_action("write_file", {"path": "/srv/App.yaml", "content": "x"})
    assert write.tool == "filesystem"
    assert write.parameters["path"] == "/srv/App.yaml"  # case preserved
    assert write.parameters["operation"] == "write"

    read = agent_loop.to_action("read_file", {"path": "/srv/a.yaml"})
    assert read.parameters["operation"] == "read"


def test_refusals_are_fed_back_as_tool_output(
    agent_loop: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    A refusal must reach the model as a result, not as a crash: a well-behaved
    agent replans, and the trajectory stays observable.
    """
    assert agent_loop.main(["--json", "--phase", "2"]) == 0
    payload = json.loads(capsys.readouterr().out)

    # The run continues past the refusal.
    steps = [d["step"] for d in payload["decisions"]]
    refused_step = next(d["step"] for d in payload["decisions"] if not d["executed"])
    assert max(steps) > refused_step


def test_example_policy_is_loadable_and_knows_the_demo_actor(agent_loop: Any) -> None:
    from aetherya.config import load_policy_config

    cfg = load_policy_config(agent_loop.POLICY_PATH)
    assert agent_loop.ACTOR in cfg.capability_matrix.actors


def test_openai_backend_requires_a_key(monkeypatch: pytest.MonkeyPatch, agent_loop: Any) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="OPENAI_API_KEY"):
        agent_loop.OpenAIAgent()
