# pip install -e ".[dev]"
# python examples/basic_tool_wrapper.py
#
# Demonstrates wrapping sensitive tool calls behind ÆTHERYA.
# Can be run from any directory — uses examples/policy.minimal.yaml.
#
# No external infrastructure required.
# Cases 1-2: default policy behavior.
# Cases 3-5: signed proof flow (escalate → sign → allow → replay deny).

import os
import tempfile
from pathlib import Path

import yaml

from aetherya.api import AetheryaAPI, APISettings

POLICY_PATH = Path(__file__).parent / "policy.minimal.yaml"
ACTOR = "robert"


# ---------------------------------------------------------------------------
# Tool wrappers — the pattern being demonstrated
# ---------------------------------------------------------------------------


def safe_delete(path: str, api: AetheryaAPI) -> str:
    """
    Wraps a destructive delete behind ÆTHERYA.
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
        raise PermissionError(decision.get("reason", decision.get("state")))
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
        raise PermissionError(decision.get("reason", decision.get("state")))
    return f"[simulated] content of {path}"


def safe_write(path: str, api: AetheryaAPI, proof: str | None = None) -> str:
    """
    Wraps a write operation.
    - Without proof (signed_proof.enabled=true): state=escalate → PermissionError
    - With valid proof: state=allow → execution proceeds
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
        raise PermissionError(decision.get("reason", decision.get("state")))
    return f"[simulated] wrote to {path}"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _case(n: int, title: str) -> None:
    print(f"\n=== CASE {n}: {title} ===")


def _result(action: str, response: dict) -> None:
    d = response.get("decision", {})
    print(f"  Action  : {action}")
    print(f"  Allowed : {d.get('allowed')}")
    print(f"  State   : {d.get('state')}")
    print(f"  Reason  : {d.get('reason')}")


# ---------------------------------------------------------------------------
# Cases 1-2: standard policy behavior
# ---------------------------------------------------------------------------


def run_standard_cases(api: AetheryaAPI) -> None:
    # Case 1 — Destructive command: ProceduralGuard → hard_deny
    _case(1, "DESTRUCTIVE COMMAND")
    raw = "mode:operative tool:shell param.command=rm -rf / --no-preserve-root"
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    _result(raw, response)
    print()
    try:
        safe_delete("/etc/passwd", api)
    except PermissionError as e:
        print(f"  PermissionError raised: {e}")

    # Case 2 — Consultive read: allowed (state=log_only in consultive mode)
    # log_only means: allowed=True, but the event is logged for review.
    _case(2, "SAFE READ (consultive mode)")
    raw = "help user read the config file"
    _, response = api.decide({"raw_input": raw, "actor": ACTOR, "wait_shadow": False})
    _result(raw, response)
    print()
    try:
        result = safe_read("/tmp/config.yaml", api)
        print(f"  Result  : {result}")
    except PermissionError as e:
        print(f"  PermissionError raised: {e}")


# ---------------------------------------------------------------------------
# Cases 3-5: confirmation flow (signed_proof.enabled=true)
# ---------------------------------------------------------------------------


def run_confirmation_cases() -> None:
    # Build a temp policy with signed_proof enabled (memory replay, single_use)
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

    # Case 3 — Write without proof: escalate (human approval required)
    _case(3, "WRITE WITHOUT PROOF (confirmation required)")
    _, response = api.decide({"raw_input": write_raw, "actor": ACTOR, "wait_shadow": False})
    _result("filesystem write /tmp/demo.txt", response)
    print()
    try:
        safe_write("/tmp/demo.txt", api)
    except PermissionError as e:
        print(f"  PermissionError raised: {e}")

    # Sign an approval proof
    sign_status, sign_resp = api.confirmation_sign(
        {"raw_input": write_raw, "actor": ACTOR, "expires_in_sec": 60},
        headers={"x-aetherya-admin-key": admin_key},
        client_ip="127.0.0.1",
    )
    if sign_status != 200 or not sign_resp.get("ok"):
        print(f"\n  [sign failed: {sign_resp}]")
        tmp_policy.unlink(missing_ok=True)
        return
    proof = sign_resp["approval_proof"]
    print(f"\n  [proof signed: {proof[:48]}...]")

    # Case 4 — Write with valid proof: allow
    _case(4, "WRITE WITH SIGNED PROOF")
    try:
        result = safe_write("/tmp/demo.txt", api, proof=proof)
        # proof consumed above; sign a fresh one just for display
        _, s2 = api.confirmation_sign(
            {"raw_input": write_raw, "actor": ACTOR, "expires_in_sec": 60},
            headers={"x-aetherya-admin-key": admin_key},
            client_ip="127.0.0.1",
        )
        p2 = s2.get("approval_proof", "")
        _, r2 = api.decide(
            {
                "raw_input": f"{write_raw} param.confirm_proof={p2}",
                "actor": ACTOR,
                "wait_shadow": False,
            }
        )
        _result("filesystem write /tmp/demo.txt [+proof]", r2)
        print()
        print(f"  Result  : {result}")
    except PermissionError as e:
        print(f"  PermissionError raised: {e}")

    # Case 5 — Replay the same consumed proof: denied
    _case(5, "REPLAY ATTACK (same proof reused)")
    _, response = api.decide(
        {
            "raw_input": f"{write_raw} param.confirm_proof={proof}",
            "actor": ACTOR,
            "wait_shadow": False,
        }
    )
    _result("filesystem write /tmp/demo.txt [replayed proof]", response)

    tmp_policy.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    api = AetheryaAPI(APISettings(policy_path=POLICY_PATH, audit_path=None))
    run_standard_cases(api)
    run_confirmation_cases()
    print("\n=== DONE ===\n")


if __name__ == "__main__":
    main()
