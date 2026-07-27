from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml

from aetherya.actions import ActionRequest, Decision
from aetherya.client import AetheryaClient, AetheryaUnavailable
from aetherya.config import load_policy_config
from aetherya.enforcement import PHASES, apply_enforcement, resolve_phase

_POLICY = "config/policy.yaml"


def _decision(state: str, *, risk: int = 0) -> Decision:
    return Decision(
        allowed=state in {"allow", "log_only"},
        risk_score=risk,
        reason=f"{state}: test",
        mode="operative",
        state=state,
    )


# ---------------------------------------------------------------------------
# Phase semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["allow", "log_only", "escalate", "deny", "hard_deny"])
def test_phase_1_never_refuses(state: str) -> None:
    """Shadow must not change behaviour, only observe it."""
    result = apply_enforcement(_decision(state), 1)
    assert result.execute is True
    assert result.requires_confirmation is False


@pytest.mark.parametrize(
    ("state", "executes"),
    [("allow", True), ("log_only", True), ("escalate", True), ("deny", True), ("hard_deny", False)],
)
def test_phase_2_refuses_only_hard_deny(state: str, executes: bool) -> None:
    assert apply_enforcement(_decision(state), 2).execute is executes


def test_phase_3_refuses_denials_and_holds_escalations() -> None:
    assert apply_enforcement(_decision("hard_deny"), 3).execute is False
    assert apply_enforcement(_decision("deny"), 3).execute is False

    held = apply_enforcement(_decision("escalate"), 3)
    assert held.execute is False
    assert held.requires_confirmation is True

    assert apply_enforcement(_decision("allow"), 3).execute is True


@pytest.mark.parametrize("state", ["hard_deny", "deny", "escalate"])
def test_shadow_gap_marks_what_a_later_phase_would_refuse(state: str) -> None:
    """The number phase 1 exists to produce."""
    assert apply_enforcement(_decision(state), 1).shadow_gap is True


@pytest.mark.parametrize("state", ["allow", "log_only"])
def test_allowed_states_are_never_a_shadow_gap(state: str) -> None:
    assert apply_enforcement(_decision(state), 1).shadow_gap is False


def test_shadow_gap_is_false_once_the_phase_enforces() -> None:
    assert apply_enforcement(_decision("hard_deny"), 2).shadow_gap is False


def test_enforcement_tightens_monotonically() -> None:
    """Each phase must refuse at least as much as the one before it."""
    states = ["allow", "log_only", "escalate", "deny", "hard_deny"]
    refused = [
        sum(1 for s in states if not apply_enforcement(_decision(s), p).execute)
        for p in sorted(PHASES)
    ]
    assert refused == sorted(refused)
    assert refused[0] == 0


def test_enforcement_never_mutates_the_decision() -> None:
    """
    The audit trail records what the engine ruled, not what a partially
    enforcing deployment did about it. Conflating them makes phase-1 data
    worthless.
    """
    decision = _decision("hard_deny", risk=164)
    apply_enforcement(decision, 1)
    assert decision.state == "hard_deny"
    assert decision.allowed is False


def test_unknown_phase_is_rejected() -> None:
    with pytest.raises(ValueError, match="enforcement.phase must be one of"):
        resolve_phase(9)


def test_policy_exposes_the_phase() -> None:
    assert load_policy_config(_POLICY).enforcement.phase == 1


def test_policy_rejects_an_invalid_phase(tmp_path: Path) -> None:
    data = yaml.safe_load(Path(_POLICY).read_text(encoding="utf-8"))
    data["enforcement"]["phase"] = 4
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match="enforcement.phase must be 1, 2 or 3"):
        load_policy_config(path)


def test_enforcement_serializes() -> None:
    payload = apply_enforcement(_decision("hard_deny"), 2).to_dict()
    assert payload["execute"] is False
    assert payload["phase"] == 2


# ---------------------------------------------------------------------------
# Sidecar client
# ---------------------------------------------------------------------------


class _Service(BaseHTTPRequestHandler):
    state = "allow"
    risk = 0
    status = 200
    body_override: str | None = None
    requests: list[dict[str, Any]] = []

    def _send(self, payload: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        self._send({"ok": True, "degraded": False, "effective_fingerprint": "sha256:test"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        type(self).requests.append(json.loads(self.rfile.read(length) or b"{}"))
        if type(self).body_override is not None:
            raw = type(self).body_override.encode("utf-8")
            self.send_response(type(self).status)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self._send(
            {
                "ok": True,
                "decision": {
                    "state": type(self).state,
                    "allowed": type(self).state in {"allow", "log_only"},
                    "risk_score": type(self).risk,
                    "reason": f"{type(self).state}: from service",
                },
            },
            type(self).status,
        )

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def service() -> Any:
    _Service.state = "allow"
    _Service.risk = 0
    _Service.status = 200
    _Service.body_override = None
    _Service.requests = []
    server = HTTPServer(("127.0.0.1", 0), _Service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


def _client(service: Any, **kwargs: Any) -> AetheryaClient:
    return AetheryaClient(f"http://127.0.0.1:{service.server_port}", actor="test-agent", **kwargs)


def _action() -> ActionRequest:
    return ActionRequest(
        raw_input="rm -rf /",
        intent="operate",
        mode_hint="operative",
        tool="shell",
        parameters={"command": "rm -rf /"},
    )


def test_client_sends_the_structured_action(service: Any) -> None:
    """No free-text parsing over the wire: the agent declares its action."""
    _client(service).check(_action())

    sent = _Service.requests[-1]
    assert sent["action"]["tool"] == "shell"
    assert sent["action"]["intent"] == "operate"
    assert sent["actor"] == "test-agent"


def test_client_applies_the_phase(service: Any) -> None:
    _Service.state = "hard_deny"
    _Service.risk = 164

    assert _client(service, phase=1).check(_action()).execute is True
    assert _client(service, phase=2).check(_action()).execute is False


def test_client_surfaces_the_shadow_gap(service: Any) -> None:
    _Service.state = "hard_deny"
    verdict = _client(service, phase=1).check(_action())

    assert verdict.execute is True
    assert verdict.shadow_gap is True
    assert verdict.refused is False


def test_client_holds_escalations_in_phase_3(service: Any) -> None:
    _Service.state = "escalate"
    verdict = _client(service, phase=3).check(_action())

    assert verdict.execute is False
    assert verdict.requires_confirmation is True


def test_refusal_carries_the_engine_reason(service: Any) -> None:
    """What goes back to the model must say why, not just that it was refused."""
    _Service.state = "hard_deny"
    verdict = _client(service, phase=2).check(_action())
    assert "from service" in verdict.reason


def test_candidate_response_is_forwarded(service: Any) -> None:
    _client(service).check(_action(), candidate_response="the answer")
    assert _Service.requests[-1]["candidate_response"] == "the answer"


# -- failure behaviour -------------------------------------------------------


def test_unreachable_service_refuses_from_phase_2(service: Any) -> None:
    """A boundary that disappears when the network hiccups is not a boundary."""
    dead = AetheryaClient("http://127.0.0.1:1", actor="a", phase=2, timeout_sec=0.5)
    verdict = dead.check(_action())

    assert verdict.execute is False
    assert "unavailable" in verdict.reason


def test_unreachable_service_proceeds_in_phase_1(service: Any) -> None:
    """Phase 1 enforces nothing, so an outage must not stop the agent."""
    dead = AetheryaClient("http://127.0.0.1:1", actor="a", phase=1, timeout_sec=0.5)
    assert dead.check(_action()).execute is True


def test_phase_1_fail_open_can_be_disabled() -> None:
    dead = AetheryaClient(
        "http://127.0.0.1:1", actor="a", phase=1, timeout_sec=0.5, fail_open_in_shadow=False
    )
    assert dead.check(_action()).execute is False


def test_an_http_error_is_treated_as_unavailable(service: Any) -> None:
    _Service.status = 500
    _Service.body_override = '{"ok": false}'
    assert _client(service, phase=2).check(_action()).execute is False


def test_a_response_without_a_decision_is_treated_as_unavailable(service: Any) -> None:
    _Service.body_override = '{"ok": true}'
    verdict = _client(service, phase=2).check(_action())
    assert verdict.execute is False
    assert verdict.state == "unavailable"


def test_a_non_object_response_is_rejected(service: Any) -> None:
    _Service.body_override = "[1, 2, 3]"
    assert _client(service, phase=2).check(_action()).execute is False


def test_health_is_readable(service: Any) -> None:
    assert _client(service).health()["ok"] is True


def test_health_raises_when_unreachable() -> None:
    dead = AetheryaClient("http://127.0.0.1:1", actor="a", timeout_sec=0.5)
    with pytest.raises(AetheryaUnavailable):
        dead.health()


def test_base_url_trailing_slash_is_normalised(service: Any) -> None:
    client = AetheryaClient(f"http://127.0.0.1:{service.server_port}/", actor="a", phase=1)
    assert client.check(_action()).state == "allow"
