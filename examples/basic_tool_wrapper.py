# pip install -e ".[dev]"
# python examples/basic_tool_wrapper.py
#
# Demonstrates wrapping sensitive tool calls with ÆTHERYA's decision pipeline.
#
# No external infrastructure required.
# Cases 1–2 use the default policy (config/policy.yaml).
# Cases 3–4 create a temporary policy in /tmp with signed_proof.enabled=true
# to show the full confirmation flow (escalate → sign → allow → replay deny).
# The temp file is cleaned up at the end.

import os
import sys
import tempfile
from pathlib import Path

import yaml

from aetherya.api import AetheryaAPI, APISettings

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
POLICY_PATH = Path("config/policy.yaml")
ACTOR = "robert"


# ---------------------------------------------------------------------------
# Tool wrappers
# ---------------------------------------------------------------------------


def safe_delete(path: str, api: AetheryaAPI) -> str:
    """
    Wraps a destructive delete operation behind ÆTHERYA.
    Raises PermissionError if the decision is not allowed.
    """
    raw = (
        f"mode:operative tool:filesystem target:{path}"
        f" param.path={path} param.operation=delete"
        f" param.confirm_token=ack:del123"
        f" param.confirm_context=operator_approved"
    )
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    decision = response.get("decision", {})
    if not decision.get("allowed"):
        raise PermissionError(f"Denied: {decision.get('reason')}  (state={decision.get('state')})")
    # Simulated — no real deletion
    return f"[simulated] deleted {path}"


def safe_read(path: str, api: AetheryaAPI) -> str:
    """
    Wraps a read operation. Consultive intent — expected to be allowed.
    Raises PermissionError if the decision is not allowed.
    """
    raw = f"help user read the config at {path}"
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    decision = response.get("decision", {})
    if not decision.get("allowed"):
        raise PermissionError(f"Denied: {decision.get('reason')}  (state={decision.get('state')})")
    # Simulated
    return f"[simulated] content of {path}"


def safe_write(path: str, api: AetheryaAPI, proof: str | None = None) -> str:
    """
    Wraps a write operation.

    When signed_proof.enabled=true in policy:
    - Without proof → decision.state="escalate", allowed=False → PermissionError
    - With valid proof → decision.state="allow", allowed=True → execution proceeds

    proof is the approval_proof string emitted by AetheryaAPI.confirmation_sign().
    """
    raw = (
        f"mode:operative tool:filesystem target:{path}"
        f" param.path={path} param.operation=write"
        f" param.confirm_token=ack:abc12345"
        f" param.confirm_context=approved_by_operator"
    )
    if proof:
        raw += f" param.confirm_proof={proof}"
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    decision = response.get("decision", {})
    if not decision.get("allowed"):
        raise PermissionError(f"Denied: {decision.get('reason')}  (state={decision.get('state')})")
    # Simulated — no real write
    return f"[simulated] wrote to {path}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print(label: str, action: str, response: dict) -> None:
    d = response.get("decision", {})
    print(f"  action : {action}")
    print(f"  allowed: {d.get('allowed')}")
    print(f"  state  : {d.get('state')}")
    print(f"  reason : {d.get('reason')}")
    print()


def _separator(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


# ---------------------------------------------------------------------------
# Cases 1–2: default policy
# ---------------------------------------------------------------------------


def run_cases_default(api: AetheryaAPI) -> None:
    # Case 1 — Destructive operation: ProceduralGuard blocks rm -rf /
    _separator("Case 1 — dangerous operation (expect: deny or hard_deny)")
    raw = "mode:operative tool:shell param.command=rm -rf / --no-preserve-root"
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    _print("1", raw, response)

    try:
        # safe_delete on a system path → ProceduralGuard / risk aggregation blocks it
        safe_delete("/etc/passwd", api)
    except PermissionError as e:
        print(f"  PermissionError: {e}\n")

    # Case 2 — Normal consultive action: expected ALLOW or LOG_ONLY
    # In consultive mode, non-operative inputs return state="log_only", allowed=True.
    # log_only means: allowed, but the event is logged for review. Execution proceeds.
    _separator("Case 2 — normal action (expect: allow or log_only)")
    raw = "help user read the config file"
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    _print("2", raw, response)

    try:
        result = safe_read("/tmp/config.yaml", api)
        print(f"  result : {result}\n")
    except PermissionError as e:
        print(f"  PermissionError: {e}\n")


# ---------------------------------------------------------------------------
# Cases 3–4: temp policy with signed_proof.enabled=true
# ---------------------------------------------------------------------------


def run_cases_confirmation() -> None:
    # Build a temporary policy with signed_proof enabled (memory replay store)
    raw_data = yaml.safe_load(POLICY_PATH.read_text())
    sp = raw_data["confirmation"]["evidence"]["signed_proof"]
    sp["enabled"] = True
    sp["replay_store"] = "memory"
    sp["replay_mode"] = "single_use"

    tmp_policy = Path(tempfile.mktemp(suffix=".yaml"))
    tmp_policy.write_text(yaml.safe_dump(raw_data, sort_keys=False))

    hmac_key = "demo-hmac-key-examples-v1"
    admin_key = "demo-admin-key"
    os.environ["AETHERYA_CONFIRMATION_HMAC_KEY"] = hmac_key
    os.environ["AETHERYA_APPROVALS_API_KEY"] = admin_key

    api = AetheryaAPI(APISettings(policy_path=tmp_policy, audit_path=None))

    write_raw = (
        "mode:operative tool:filesystem target:/tmp/demo.txt"
        " param.path=/tmp/demo.txt param.operation=write"
        " param.confirm_token=ack:abc12345"
        " param.confirm_context=approved_by_operator"
    )

    # Case 3 — Sensitive write without proof (expect: escalate, allowed=False)
    _separator("Case 3 — sensitive write, no proof (expect: escalate)")
    _, response = api.decide({"raw_input": write_raw, "actor": ACTOR, "wait_shadow": False})
    _print("3", write_raw[:55] + "...", response)

    try:
        safe_write("/tmp/demo.txt", api)
    except PermissionError as e:
        print(f"  PermissionError: {e}\n")

    # Sign the proof
    sign_status, sign_resp = api.confirmation_sign(
        {"raw_input": write_raw, "actor": ACTOR, "expires_in_sec": 60},
        headers={"x-aetherya-admin-key": admin_key},
        client_ip="127.0.0.1",
    )
    if sign_status != 200 or not sign_resp.get("ok"):
        print(f"  [sign failed: {sign_resp}]")
        tmp_policy.unlink(missing_ok=True)
        return

    proof = sign_resp["approval_proof"]
    print(f"  [proof signed: {proof[:48]}...]\n")

    # Case 4 — Same write with valid proof (expect: allow)
    _separator("Case 4 — sensitive write with signed proof (expect: allow)")
    _, response = api.decide(
        {
            "raw_input": f"{write_raw} param.confirm_proof={proof}",
            "actor": ACTOR,
            "wait_shadow": False,
        }
    )
    _print("4", write_raw[:55] + "...[+proof]", response)

    # NOTE: the proof was already consumed by the decide() call above (single_use mode).
    # safe_write() will try to use it again → replay rejected (expected and correct).
    # In a real integration you would either:
    #   a) call safe_write() with the proof directly (skip the manual decide() call above), or
    #   b) sign a fresh proof for safe_write() separately.
    try:
        result = safe_write("/tmp/demo.txt", api, proof=proof)
        print(f"  result : {result}\n")
    except PermissionError as e:
        print(f"  PermissionError (proof already consumed — expected): {e}\n")

    # Case 5 — Replay attempt with the same proof (expect: deny)
    _separator("Case 5 — replay attack with consumed proof (expect: deny/escalate)")
    _, response = api.decide(
        {
            "raw_input": f"{write_raw} param.confirm_proof={proof}",
            "actor": ACTOR,
            "wait_shadow": False,
        }
    )
    _print("5 [replay]", write_raw[:55] + "...[+proof]", response)

    tmp_policy.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    if not POLICY_PATH.exists():
        print(
            f"Policy not found: {POLICY_PATH}\n"
            "Run from the repo root:  python examples/basic_tool_wrapper.py",
            file=sys.stderr,
        )
        sys.exit(1)

    api = AetheryaAPI(APISettings(policy_path=POLICY_PATH, audit_path=None))

    run_cases_default(api)
    run_cases_confirmation()

    print("\n✓ done\n")


if __name__ == "__main__":
    main()
