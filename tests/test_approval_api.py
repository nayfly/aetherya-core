from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from aetherya.api import AetheryaAPI, APISettings
from aetherya.api_server import build_server
from aetherya.approval_queue import ApprovalQueue

# ---------------------------------------------------------------------------
# The HTTP halves of the approval flow, and the trust boundary between them:
# an agent parks a held action, an operator answers it. Those are different
# parties with different keys, and answering mints a credential.
# ---------------------------------------------------------------------------

HMAC_KEY = "test-approval-signing-key-0123456789"

ACTION = {
    "raw_input": "write file /srv/app/config.PROD.yaml",
    "intent": "operate",
    "tool": "filesystem",
    "target": "/srv/app/config.PROD.yaml",
    "parameters": {"operation": "write"},
}


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    """A policy with signed proofs on — an approval cannot mint one otherwise."""
    source = Path("config/policy.yaml").read_text(encoding="utf-8")
    patched = source.replace(
        "    signed_proof:\n      enabled: false",
        "    signed_proof:\n      enabled: true",
    )
    assert patched != source, "policy.yaml no longer has signed_proof.enabled: false"
    path = tmp_path / "policy.yaml"
    path.write_text(patched, encoding="utf-8")
    return path


def _api(tmp_path: Path, policy_path: Path) -> AetheryaAPI:
    return AetheryaAPI(
        APISettings(
            policy_path=policy_path,
            audit_path=tmp_path / "decisions.jsonl",
            review_path=tmp_path / "reviews.jsonl",
            approval_queue_path=tmp_path / "approvals.jsonl",
        )
    )


def _submit(api: AetheryaAPI) -> str:
    code, body = api.submit_approval(
        {"actor": "robert", "action": ACTION, "state": "escalate", "risk_score": 63}
    )
    assert code == 200, body
    return str(body["request"]["request_id"])


# ---------------------------------------------------------------------------
# Submitting and polling — the agent's side
# ---------------------------------------------------------------------------


def test_an_agent_parks_a_held_action_and_polls_it(tmp_path: Path, policy: Path) -> None:
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, body = api.approval_status({"request_id": request_id})
    assert code == 200
    assert body["request"]["status"] == "pending"
    assert body["request"]["actor"] == "robert"


def test_the_full_structured_action_is_required(tmp_path: Path, policy: Path) -> None:
    """
    The proof is scoped to the exact action, so a description of it would mint
    something the agent cannot use.
    """
    api = _api(tmp_path, policy)
    assert api.submit_approval({"actor": "robert", "action": "write the file"})[0] == 400
    assert api.submit_approval({"actor": "robert"})[0] == 400
    assert api.submit_approval({"actor": "robert", "action": {"intent": "operate"}})[0] == 400


def test_polling_an_unknown_request_is_a_404(tmp_path: Path, policy: Path) -> None:
    code, body = _api(tmp_path, policy).approval_status({"request_id": "apr_nope"})
    assert code == 404
    assert "no approval request" in body["error"]


def test_polling_without_a_request_id_is_a_400(tmp_path: Path, policy: Path) -> None:
    assert _api(tmp_path, policy).approval_status({})[0] == 400


def test_the_queue_can_be_disabled(tmp_path: Path, policy: Path) -> None:
    api = AetheryaAPI(APISettings(policy_path=policy, approval_queue_path=None))
    for code, body in [
        api.submit_approval({"actor": "a", "action": ACTION}),
        api.pending_approvals(),
        api.approval_status({"request_id": "apr_x"}),
    ]:
        assert code == 400
        assert "approval_queue_path is disabled" in body["error"]


# ---------------------------------------------------------------------------
# Listing — the operator's view
# ---------------------------------------------------------------------------


def test_pending_approvals_carry_the_stats_phase_3_asks_for(tmp_path: Path, policy: Path) -> None:
    api = _api(tmp_path, policy)
    _submit(api)
    _submit(api)

    code, body = api.pending_approvals()
    assert code == 200
    assert body["count"] == 2
    assert body["stats"]["pending"] == 2
    assert body["stats"]["expired"] == 0


# ---------------------------------------------------------------------------
# Answering — privileged
# ---------------------------------------------------------------------------


def _admin(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("AETHERYA_APPROVALS_API_KEY", "admin-key")
    monkeypatch.setenv("AETHERYA_CONFIRMATION_HMAC_KEY", HMAC_KEY)
    return {"headers": {"X-AETHERYA-Admin-Key": "admin-key"}, "client_ip": "127.0.0.1"}


def test_approving_mints_a_proof_the_engine_would_accept(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The point of the whole flow: the proof has to verify against the action it
    was minted for, or the agent's retry is refused and the approval was theatre.
    """
    from aetherya.actions import ActionRequest
    from aetherya.approval_proof import approval_scope_hash, verify_approval_proof
    from aetherya.config import load_policy_config

    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, body = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"}, **admin
    )
    assert code == 200, body
    proof = body["request"]["proof"]
    assert proof

    signed_cfg = load_policy_config(policy).confirmation.evidence.signed_proof
    action = ActionRequest(
        raw_input=ACTION["raw_input"],  # type: ignore[arg-type]
        intent="operate",
        tool="filesystem",
        target=ACTION["target"],  # type: ignore[arg-type]
        parameters={"operation": "write"},
    )
    # Verification signals failure by raising, so reaching the assertions below
    # is the whole result: the proof is well formed, in date, and scoped to this
    # exact actor and action.
    verification = verify_approval_proof(
        proof=proof,
        keyring={signed_cfg.active_kid: HMAC_KEY},
        actor="robert",
        action=action,
        max_valid_for_sec=signed_cfg.max_valid_for_sec,
    )
    assert verification.kid == signed_cfg.active_kid
    assert verification.scope_hash == approval_scope_hash(actor="robert", action=action)


def test_a_proof_does_not_verify_against_a_different_action(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The scope is the point. A proof approving a write to config.PROD.yaml must
    not authorise a write to anything else.
    """
    from aetherya.actions import ActionRequest
    from aetherya.approval_proof import ApprovalProofError, verify_approval_proof
    from aetherya.config import load_policy_config

    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)
    proof = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"}, **admin
    )[1]["request"]["proof"]

    signed_cfg = load_policy_config(policy).confirmation.evidence.signed_proof
    elsewhere = ActionRequest(
        raw_input="write file /srv/app/other.yaml",
        intent="operate",
        tool="filesystem",
        target="/srv/app/other.yaml",
        parameters={"operation": "write"},
    )
    with pytest.raises(ApprovalProofError):
        verify_approval_proof(
            proof=proof,
            keyring={signed_cfg.active_kid: HMAC_KEY},
            actor="robert",
            action=elsewhere,
            max_valid_for_sec=signed_cfg.max_valid_for_sec,
        )


def test_the_proof_is_returned_once_and_never_stored(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    body = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"}, **admin
    )[1]
    proof = body["request"]["proof"]

    assert proof not in (tmp_path / "approvals.jsonl").read_text(encoding="utf-8")
    assert "proof" not in api.approval_status({"request_id": request_id})[1]["request"]


def test_rejecting_records_the_reason_and_mints_nothing(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, body = api.resolve_approval(
        {
            "request_id": request_id,
            "approved": False,
            "decided_by": "robert",
            "note": "that is PROD, use staging",
        },
        **admin,
    )
    assert code == 200
    assert body["request"]["status"] == "rejected"
    assert "proof" not in body["request"]


def test_a_rejection_without_a_reason_is_refused(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, body = api.resolve_approval(
        {"request_id": request_id, "approved": False, "decided_by": "robert"}, **admin
    )
    assert code == 400
    assert "must explain why" in body["error"]


def test_answering_twice_is_a_conflict(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two proofs for one authorisation is the replay single-use exists to stop."""
    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)
    decision = {"request_id": request_id, "approved": True, "decided_by": "robert"}

    assert api.resolve_approval(decision, **admin)[0] == 200
    code, body = api.resolve_approval(decision, **admin)
    assert code == 409
    assert "already approved" in body["error"]


def test_answering_an_unknown_request_is_a_404(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = _admin(monkeypatch)
    code, _ = _api(tmp_path, policy).resolve_approval(
        {"request_id": "apr_nope", "approved": True, "decided_by": "robert"}, **admin
    )
    assert code == 404


def test_answering_requires_the_admin_key(tmp_path: Path, policy: Path) -> None:
    """
    Reading the queue takes the console key; authorising an irreversible action
    on someone's behalf takes more than that.
    """
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, _ = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"},
        headers={},
        client_ip="127.0.0.1",
    )
    assert code == 503  # no admin key configured at all

    code, _ = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"},
        headers={"X-AETHERYA-Admin-Key": "wrong"},
        client_ip="10.0.0.5",
    )
    assert code == 403  # not localhost


def test_a_credential_cannot_be_recorded_as_the_approver(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same rule as the review store: the queue is part of the audit surface."""
    admin = _admin(monkeypatch)
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, body = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": HMAC_KEY}, **admin
    )
    assert code == 400
    assert "contains a credential" in body["error"]


def test_an_approval_cannot_mint_a_proof_the_policy_would_reject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    With signed proofs disabled the engine will not accept one, so approving
    would hand the agent something guaranteed to be refused.
    """
    admin = _admin(monkeypatch)
    api = _api(tmp_path, Path("config/policy.yaml"))
    request_id = _submit(api)

    code, body = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"}, **admin
    )
    assert code == 400
    assert "signed_proof.enabled=false" in body["error"]


def test_a_missing_signing_key_is_reported(
    tmp_path: Path, policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AETHERYA_APPROVALS_API_KEY", "admin-key")
    monkeypatch.delenv("AETHERYA_CONFIRMATION_HMAC_KEY", raising=False)
    api = _api(tmp_path, policy)
    request_id = _submit(api)

    code, body = api.resolve_approval(
        {"request_id": request_id, "approved": True, "decided_by": "robert"},
        headers={"X-AETHERYA-Admin-Key": "admin-key"},
        client_ip="127.0.0.1",
    )
    assert code == 400
    assert "missing approval signing key" in body["error"]


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


@pytest.fixture
def server(tmp_path: Path, policy: Path) -> Any:
    api = _api(tmp_path, policy)
    srv = build_server(host="127.0.0.1", port=0, api=api, max_body_bytes=65536)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _request(
    srv: Any,
    path: str,
    payload: Any = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(  # noqa: S310
        f"http://127.0.0.1:{srv.server_port}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def test_the_agent_endpoints_round_trip_over_http(server: Any) -> None:
    status, body = _request(
        server,
        "/v1/approvals/request",
        {"actor": "robert", "action": ACTION, "state": "escalate", "risk_score": 63},
        "POST",
    )
    assert status == 200
    request_id = json.loads(body)["request"]["request_id"]

    status, body = _request(server, f"/v1/approvals/status?request_id={request_id}")
    assert status == 200
    assert json.loads(body)["request"]["status"] == "pending"


def test_the_pending_list_is_served(server: Any) -> None:
    _request(server, "/v1/approvals/request", {"actor": "robert", "action": ACTION}, "POST")
    status, body = _request(server, "/v1/approvals/pending")
    assert status == 200
    assert json.loads(body)["count"] == 1


def test_the_pending_list_honours_the_console_key(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "s3cret")
    assert _request(server, "/v1/approvals/pending")[0] == 401
    status, _ = _request(
        server, "/v1/approvals/pending", None, "GET", {"X-AETHERYA-Console-Key": "s3cret"}
    )
    assert status == 200


def test_resolving_over_http_requires_the_admin_key(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AETHERYA_APPROVALS_API_KEY", "admin-key")
    monkeypatch.setenv("AETHERYA_CONFIRMATION_HMAC_KEY", HMAC_KEY)
    _, body = _request(
        server, "/v1/approvals/request", {"actor": "robert", "action": ACTION}, "POST"
    )
    request_id = json.loads(body)["request"]["request_id"]
    decision = {"request_id": request_id, "approved": True, "decided_by": "robert"}

    assert _request(server, "/v1/approvals/resolve", decision, "POST")[0] == 401
    status, body = _request(
        server, "/v1/approvals/resolve", decision, "POST", {"X-AETHERYA-Admin-Key": "admin-key"}
    )
    assert status == 200
    assert json.loads(body)["request"]["proof"]


def test_the_wrong_method_is_refused(server: Any) -> None:
    assert _request(server, "/v1/approvals/request")[0] == 405
    assert _request(server, "/v1/approvals/status", {}, "POST")[0] == 405
    assert _request(server, "/v1/approvals/resolve", None, "GET")[0] == 405


def test_a_malformed_submission_body_is_a_400(server: Any) -> None:
    request = urllib.request.Request(  # noqa: S310
        f"http://127.0.0.1:{server.server_port}/v1/approvals/request",
        data=b"{broken",
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=5)  # noqa: S310
    assert exc.value.code == 400


def test_an_oversized_submission_is_refused(server: Any) -> None:
    request = urllib.request.Request(  # noqa: S310
        f"http://127.0.0.1:{server.server_port}/v1/approvals/request",
        data=b"{}",
        method="POST",
        headers={"Content-Length": "99999999"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=5)  # noqa: S310
    assert exc.value.code == 413


def test_the_approval_routes_answer_when_the_api_is_missing() -> None:
    import io

    from aetherya.api_server import AetheryaHTTPRequestHandler

    class _Bare(AetheryaHTTPRequestHandler):
        def __init__(self, path: str, command: str) -> None:
            self.api = None
            self.command = command
            self.path = path
            self.headers = {}  # type: ignore[assignment]
            self.sent: list[tuple[int, dict[str, Any]]] = []
            self.wfile = io.BytesIO()

        def _send_json(self, status: int, body: dict[str, Any]) -> None:  # type: ignore[override]
            self.sent.append((status, body))

    for path, command in [
        ("/v1/approvals/pending", "GET"),
        ("/v1/approvals/status", "GET"),
        ("/v1/approvals/request", "POST"),
    ]:
        handler = _Bare(path, command)
        handler._handle_request()  # noqa: SLF001
        assert handler.sent[0][0] == 500, path


def test_the_ttl_comes_from_the_policy(tmp_path: Path, policy: Path) -> None:
    """
    An approval window longer than the proof's own validity would hand out
    something already expired.
    """
    from aetherya.config import load_policy_config

    api = _api(tmp_path, policy)
    _submit(api)
    expected = load_policy_config(policy).confirmation.evidence.signed_proof.max_valid_for_sec
    assert ApprovalQueue(tmp_path / "approvals.jsonl", ttl_seconds=expected).ttl_seconds == expected


def test_the_resolve_route_can_be_disabled(tmp_path: Path, policy: Path) -> None:
    """The decision profile serves no approval routes; the split must hold."""
    api = AetheryaAPI(
        APISettings(
            policy_path=policy,
            approval_queue_path=tmp_path / "approvals.jsonl",
            enable_approval_routes=False,
        )
    )
    code, body = api.dispatch(
        "POST", "/v1/approvals/resolve", {}, headers={}, client_ip="127.0.0.1"
    )
    assert code == 404
    assert "route not found" in body["error"]
