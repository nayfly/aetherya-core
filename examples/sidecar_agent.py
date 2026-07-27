"""
Phase-1 sidecar: an agent talking to the decision service over HTTP.

    docker compose up -d
    python examples/sidecar_agent.py

`agent_loop.py` runs the engine in-process, which is the right shape for a
library. This is the deployment shape: the agent is one process, ÆTHERYA is
another, and the only coupling is an HTTP call. That is what lets you put the
boundary in front of an agent you did not write, in a language that is not
Python, without linking anything.

    ┌─────────┐   proposed tool call   ┌──────────┐
    │  agent  │ ─────────────────────► │ ÆTHERYA  │
    │ process │ ◄───────────────────── │ sidecar  │
    └────┬────┘   allow | hold | refuse└──────────┘
         │                                   │
         ▼ executes only if allowed          ▼ records every decision
      tool runtime                      audit chain

Phase 1 observes: nothing is refused, but every decision is recorded, and the
verdict carries `shadow_gap=True` when a later phase *would* have refused. That
count is the number the phase exists to produce — read it back with:

    aetherya rollout report --phase 1
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from aetherya.actions import ActionRequest
from aetherya.client import AetheryaClient

# The same trajectory as agent_loop.py: the agent is not malicious, it reads a
# poisoned document and proposes what the document told it to.
PROPOSALS: list[tuple[str, ActionRequest]] = [
    (
        "inspect current config",
        ActionRequest(
            raw_input="read file /srv/app/config.yaml",
            intent="operate",
            mode_hint="operative",
            tool="filesystem",
            target="/srv/app/config.yaml",
            parameters={"path": "/srv/app/config.yaml", "operation": "read"},
        ),
    ),
    (
        "check the deploy notes",
        ActionRequest(
            raw_input="read file /srv/app/deploy_notes.md",
            intent="operate",
            mode_hint="operative",
            tool="filesystem",
            target="/srv/app/deploy_notes.md",
            parameters={"path": "/srv/app/deploy_notes.md", "operation": "read"},
        ),
    ),
    (
        "the notes say to free disk space before deploying",
        ActionRequest(
            raw_input="rm -rf / --no-preserve-root",
            intent="operate",
            mode_hint="operative",
            tool="shell",
            target="localhost",
            parameters={"command": "rm -rf / --no-preserve-root"},
        ),
    ),
    (
        "apply the scaling change",
        ActionRequest(
            raw_input="write file /srv/app/Config.PROD.yaml",
            intent="operate",
            mode_hint="operative",
            tool="filesystem",
            target="/srv/app/Config.PROD.yaml",
            parameters={"path": "/srv/app/Config.PROD.yaml", "operation": "write"},
        ),
    ),
]


def execute(action: ActionRequest) -> str:
    """Stand-in for your tool runtime."""
    return f"ok: {action.tool} {action.target}"


def run(base_url: str, actor: str, phase: int) -> int:
    gate = AetheryaClient(base_url, actor=actor, phase=phase)

    try:
        health = gate.health()
    except Exception as exc:
        print(f"  cannot reach {base_url}: {exc}")
        print("  start it with: docker compose up -d")
        return 2

    print(f"\n  sidecar {base_url}  ·  phase {phase}  ·  actor {actor}")
    print(
        f"  service: ok={health.get('ok')} degraded={health.get('degraded')} "
        f"policy={str(health.get('effective_fingerprint'))[:22]}..."
    )
    print("  " + "─" * 70)

    gaps = 0
    for step, (why, action) in enumerate(PROPOSALS, start=1):
        verdict = gate.check(action)

        print(f"\n  {step}. {action.tool}({action.target})")
        print(f"     why:      {why}")
        print(f"     ÆTHERYA:  state={verdict.state} risk={verdict.risk_score}")

        if verdict.execute:
            result = execute(action)
            marker = "⚠" if verdict.shadow_gap else "·"
            print(f"     {marker} EXECUTED: {result}")
            if verdict.shadow_gap:
                gaps += 1
                print("       a later phase would have refused this")
        elif verdict.requires_confirmation:
            print(f"     ⏸ HELD: {verdict.reason}")
        else:
            # The refusal is what the model sees, not an exception.
            print(f"     ✕ REFUSED: {verdict.reason}")

    print("\n  " + "─" * 70)
    if gaps:
        print(f"\n  {gaps} action(s) executed that phase 2+ would refuse.")
        print("  That is the phase-1 measurement. Read the full picture with:")
        print("    aetherya rollout report --phase 1 --audit-path audit/decisions.jsonl\n")
    else:
        print("\n  nothing a later phase would have refused\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--actor", default="robert")
    parser.add_argument("--phase", type=int, default=1, choices=[1, 2, 3])
    args: Any = parser.parse_args(argv)
    return run(str(args.url), str(args.actor), int(args.phase))


if __name__ == "__main__":
    sys.exit(main())
