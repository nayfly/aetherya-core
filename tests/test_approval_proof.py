from __future__ import annotations

import pytest

from aetherya.actions import ActionRequest
from aetherya.approval_proof import (
    ApprovalProofError,
    approval_scope_hash,
    build_approval_proof,
    verify_approval_proof,
)


def _make_action() -> ActionRequest:
    return ActionRequest(
        raw_input="mode:operative tool:filesystem target:/tmp param.operation=write param.path=/tmp/a",
        intent="operate",
        mode_hint="operative",
        tool="filesystem",
        target="/tmp",
        parameters={
            "operation": "write",
            "path": "/tmp/a",
            "confirm_token": "ack:abc12345",
            "confirm_context": "approved_for_sensitive_action",
        },
    )


def test_approval_proof_roundtrip_ok() -> None:
    action = _make_action()
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="top-secret",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=1_700_000_000,
        nonce="seed001",
        exclude_params=excluded,
    )

    verification = verify_approval_proof(
        secret="top-secret",
        proof=proof,
        actor="robert",
        action=action,
        now_ts=1_700_000_010,
        max_valid_for_sec=300,
        exclude_params=excluded,
    )
    assert verification.proof_version == "ap1"
    assert verification.nonce == "seed001"
    assert verification.scope_hash.startswith("sha256:")


def test_approval_proof_rejects_signature_mismatch() -> None:
    action = _make_action()
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="top-secret",
        actor="robert",
        action=action,
        ttl_sec=60,
        now_ts=1_700_000_000,
        nonce="seed001",
        exclude_params=excluded,
    )
    bad_proof = proof[:-1] + ("0" if proof[-1] != "0" else "1")

    with pytest.raises(ApprovalProofError) as exc_info:
        verify_approval_proof(
            secret="top-secret",
            proof=bad_proof,
            actor="robert",
            action=action,
            now_ts=1_700_000_010,
            exclude_params=excluded,
        )
    assert exc_info.value.code == "invalid_signature"


def test_approval_proof_rejects_expired() -> None:
    action = _make_action()
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="top-secret",
        actor="robert",
        action=action,
        ttl_sec=10,
        now_ts=1_700_000_000,
        nonce="seed001",
        exclude_params=excluded,
    )
    with pytest.raises(ApprovalProofError) as exc_info:
        verify_approval_proof(
            secret="top-secret",
            proof=proof,
            actor="robert",
            action=action,
            now_ts=1_700_000_100,
            exclude_params=excluded,
        )
    assert exc_info.value.code == "expired"


def test_approval_proof_rejects_future_window_too_large() -> None:
    action = _make_action()
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    proof, _ = build_approval_proof(
        secret="top-secret",
        actor="robert",
        action=action,
        ttl_sec=1200,
        now_ts=1_700_000_000,
        nonce="seed001",
        exclude_params=excluded,
    )
    with pytest.raises(ApprovalProofError) as exc_info:
        verify_approval_proof(
            secret="top-secret",
            proof=proof,
            actor="robert",
            action=action,
            now_ts=1_700_000_010,
            max_valid_for_sec=300,
            exclude_params=excluded,
        )
    assert exc_info.value.code == "window_too_large"


def test_approval_scope_hash_ignores_confirmation_params_when_excluded() -> None:
    action = _make_action()
    excluded = {name for name in action.parameters if name.startswith("confirm_")}
    hash_a = approval_scope_hash(actor="robert", action=action, exclude_params=excluded)

    action.parameters["confirm_context"] = "different_approval_context"
    action.parameters["confirm_token"] = "ack:zzz99999"
    hash_b = approval_scope_hash(actor="robert", action=action, exclude_params=excluded)
    assert hash_a == hash_b


def test_approval_scope_hash_changes_when_action_payload_changes() -> None:
    action_a = _make_action()
    action_b = _make_action()
    action_b.parameters["path"] = "/tmp/other"
    excluded = {name for name in action_a.parameters if name.startswith("confirm_")}
    hash_a = approval_scope_hash(actor="robert", action=action_a, exclude_params=excluded)
    hash_b = approval_scope_hash(actor="robert", action=action_b, exclude_params=excluded)
    assert hash_a != hash_b


def test_approval_scope_hash_normalizes_complex_parameter_types() -> None:
    class _CustomObj:
        def __str__(self) -> str:
            return "custom-obj"

    action = ActionRequest(
        raw_input="run",
        intent="operate",
        tool="filesystem",
        parameters={
            "dict_value": {"b": 2, "a": [1, {"x": (3, 4)}]},
            "list_value": [1, {"k": "v"}],
            "tuple_value": (1, 2, 3),
            "object_value": _CustomObj(),
        },
    )
    scope_hash = approval_scope_hash(actor="robert", action=action)
    assert scope_hash.startswith("sha256:")


def test_build_approval_proof_rejects_invalid_inputs() -> None:
    action = _make_action()
    with pytest.raises(ValueError, match="ttl_sec must be > 0"):
        build_approval_proof(
            secret="top-secret",
            actor="robert",
            action=action,
            ttl_sec=0,
        )
    with pytest.raises(ValueError, match="secret must be non-empty"):
        build_approval_proof(
            secret="   ",
            actor="robert",
            action=action,
            ttl_sec=10,
        )


@pytest.mark.parametrize(
    ("proof", "expected_code"),
    [
        ("ap1.1.a", "bad_format"),
        ("ap2.1.nonce." + ("a" * 64), "bad_version"),
        ("ap1.xyz.nonce." + ("a" * 64), "bad_expiry"),
        ("ap1.0.nonce." + ("a" * 64), "bad_expiry"),
        ("ap1.1.." + ("a" * 64), "bad_nonce"),
        ("ap1.1.nonce.deadbeef", "bad_signature"),
    ],
)
def test_verify_approval_proof_rejects_bad_formats(proof: str, expected_code: str) -> None:
    action = _make_action()
    with pytest.raises(ApprovalProofError) as exc_info:
        verify_approval_proof(
            secret="top-secret",
            proof=proof,
            actor="robert",
            action=action,
            now_ts=1,
        )
    assert exc_info.value.code == expected_code


def test_verify_approval_proof_rejects_invalid_runtime_windows() -> None:
    action = _make_action()
    with pytest.raises(ApprovalProofError) as missing_secret:
        verify_approval_proof(
            secret="   ",
            proof="ap1.1.nonce." + ("a" * 64),
            actor="robert",
            action=action,
            now_ts=1,
        )
    assert missing_secret.value.code == "missing_secret"

    with pytest.raises(ApprovalProofError) as missing_proof:
        verify_approval_proof(
            secret="top-secret",
            proof="   ",
            actor="robert",
            action=action,
            now_ts=1,
        )
    assert missing_proof.value.code == "missing_proof"

    with pytest.raises(ApprovalProofError) as invalid_window_a:
        verify_approval_proof(
            secret="top-secret",
            proof="ap1.1.nonce." + ("a" * 64),
            actor="robert",
            action=action,
            now_ts=1,
            max_valid_for_sec=0,
        )
    assert invalid_window_a.value.code == "invalid_window"

    with pytest.raises(ApprovalProofError) as invalid_window_b:
        verify_approval_proof(
            secret="top-secret",
            proof="ap1.1.nonce." + ("a" * 64),
            actor="robert",
            action=action,
            now_ts=1,
            clock_skew_sec=-1,
        )
    assert invalid_window_b.value.code == "invalid_window"
