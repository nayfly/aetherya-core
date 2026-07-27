from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aetherya.api import AetheryaAPI, APISettings
from aetherya.audit import AuditLogger
from aetherya.console import console_html


def _api(tmp_path: Path, audit: Path | None = None) -> AetheryaAPI:
    return AetheryaAPI(
        APISettings(
            policy_path=Path("config/policy.yaml"),
            audit_path=audit if audit is not None else tmp_path / "decisions.jsonl",
        )
    )


def _seed(path: Path, rows: list[tuple[str, str]]) -> None:
    """rows: (actor, state)."""
    logger = AuditLogger(str(path), policy_fingerprint="sha256:test")
    for actor, state in rows:
        logger.log(
            actor=actor,
            action=f"{state} action by {actor}",
            decision={
                "allowed": state in {"allow", "log_only"},
                "risk_score": 171 if state == "hard_deny" else 0,
                "reason": f"{state}: because",
                "state": state,
            },
            context={"mode": "operative", "action": {"tool": "shell"}},
        )


# ---------------------------------------------------------------------------
# Decision feed
# ---------------------------------------------------------------------------


def test_decisions_are_returned_newest_first(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("first", "allow"), ("second", "allow"), ("third", "hard_deny")])

    code, body = _api(tmp_path, audit).decisions()
    assert code == 200
    assert [d["actor"] for d in body["decisions"]] == ["third", "second", "first"]


def test_decisions_can_be_filtered_by_state(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow"), ("b", "hard_deny"), ("c", "allow"), ("d", "hard_deny")])

    _, body = _api(tmp_path, audit).decisions({"state": "hard_deny"})
    assert body["count"] == 2
    assert {d["actor"] for d in body["decisions"]} == {"b", "d"}


def test_decisions_respect_the_limit(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [(f"a{i}", "allow") for i in range(30)])

    _, body = _api(tmp_path, audit).decisions({"limit": 5})
    assert body["count"] == 5


def test_the_limit_is_clamped(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow")])
    api = _api(tmp_path, audit)

    assert api.decisions({"limit": 0})[1]["ok"] is True
    assert api.decisions({"limit": 99_999})[1]["ok"] is True


def test_decisions_expose_the_fields_the_console_renders(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("bot", "hard_deny")])

    row = _api(tmp_path, audit).decisions()[1]["decisions"][0]
    for field in ("ts", "actor", "action", "state", "risk_score", "reason", "tool"):
        assert field in row


def test_a_missing_audit_file_yields_an_empty_feed(tmp_path: Path) -> None:
    """A fresh deployment has no decisions yet; that is not an error."""
    code, body = _api(tmp_path, tmp_path / "nothing-here.jsonl").decisions()
    assert code == 200
    assert body["count"] == 0


def test_malformed_lines_are_skipped_in_the_feed(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow")])
    with audit.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
        handle.write("\n")
        handle.write('"bare string"\n')

    assert _api(tmp_path, audit).decisions()[1]["count"] == 1


def test_actions_are_truncated_in_the_feed(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    AuditLogger(str(audit)).log(
        actor="a",
        action="x" * 900,
        decision={"allowed": True, "risk_score": 0, "reason": "ok", "state": "allow"},
        context={},
    )
    assert len(_api(tmp_path, audit).decisions()[1]["decisions"][0]["action"]) <= 400


def test_escalated_requests_are_flagged(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    AuditLogger(str(audit)).log(
        actor="a",
        action="dd if=/dev/zero of=/dev/sda",
        decision={"allowed": False, "risk_score": 100, "reason": "bad", "state": "hard_deny"},
        context={"intent_escalation": {"escalated": True}},
    )
    assert _api(tmp_path, audit).decisions()[1]["decisions"][0]["escalated"] is True


def test_decisions_fail_when_audit_is_disabled(tmp_path: Path) -> None:
    api = AetheryaAPI(APISettings(audit_path=None))
    code, body = api.decisions()
    assert code == 400
    assert "audit_path is disabled" in body["error"]


# ---------------------------------------------------------------------------
# Rollout endpoint
# ---------------------------------------------------------------------------


def test_rollout_report_is_served(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow"), ("b", "hard_deny")])

    code, body = _api(tmp_path, audit).rollout()
    assert code == 200
    report = body["report"]
    assert report["states"] == {"allow": 1, "hard_deny": 1}
    assert report["ready_to_advance"] is False
    assert len(report["hard_deny_events"]) == 1


def test_rollout_defaults_to_the_configured_phase(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow")])

    body = _api(tmp_path, audit).rollout()[1]
    assert body["report"]["current_phase"] == 1


def test_rollout_phase_can_be_overridden(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow")])

    body = _api(tmp_path, audit).rollout({"phase": 2})[1]
    assert body["report"]["current_phase"] == 2


def test_rollout_reports_a_missing_audit_file(tmp_path: Path) -> None:
    code, body = _api(tmp_path, tmp_path / "nope.jsonl").rollout()
    assert code == 400
    assert "audit file not found" in body["error"]


def test_rollout_fails_when_audit_is_disabled() -> None:
    code, body = AetheryaAPI(APISettings(audit_path=None)).rollout()
    assert code == 400
    assert "audit_path is disabled" in body["error"]


def test_rollout_accepts_custom_thresholds(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow")] * 3)

    body = _api(tmp_path, audit).rollout({"min_decisions": 1, "min_days": 0.0})[1]
    window = next(c for c in body["report"]["criteria"] if c["name"] == "sufficient_window")
    assert window["passed"] is True


# ---------------------------------------------------------------------------
# The page itself
# ---------------------------------------------------------------------------


def test_console_page_is_self_contained() -> None:
    """
    No build step and no external assets: the page ships with the engine, so a
    deployment is one container and the audit trail sits behind one boundary.
    """
    html = console_html()
    assert "<!doctype html>" in html.lower()
    assert 'src="http' not in html
    assert 'href="http' not in html
    assert "cdn" not in html.lower()


def test_console_page_calls_the_endpoints_it_needs() -> None:
    html = console_html()
    for endpoint in ("/health", "/v1/decisions", "/v1/rollout/report"):
        assert endpoint in html


def test_console_page_escapes_rendered_values() -> None:
    """The feed renders actor-supplied strings; they must not be injected raw."""
    html = console_html()
    assert "const esc" in html
    assert "&amp;lt;" in html or "&lt;" in html


def test_console_warns_about_exposure() -> None:
    assert "Do not expose this port publicly" in console_html()


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    import threading

    from aetherya.api_server import build_server

    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow"), ("b", "hard_deny")])
    api = _api(tmp_path, audit)
    server = build_server(host="127.0.0.1", port=0, api=api, max_body_bytes=65536)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _get(server: Any, path: str, headers: dict[str, str] | None = None) -> Any:
    import urllib.request

    request = urllib.request.Request(  # noqa: S310
        f"http://127.0.0.1:{server.server_port}{path}", headers=headers or {}
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # type: ignore[name-defined]
        return exc.code, exc.read().decode("utf-8")


def test_console_is_served_at_the_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _server(tmp_path, monkeypatch)
    try:
        for path in ("/", "/console", "/dashboard"):
            status, body = _get(server, path)
            assert status == 200
            assert "Operator Console" in body
    finally:
        server.shutdown()


def test_decisions_endpoint_is_reachable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _server(tmp_path, monkeypatch)
    try:
        status, body = _get(server, "/v1/decisions?limit=5&state=hard_deny")
        assert status == 200
        payload = json.loads(body)
        assert payload["count"] == 1
    finally:
        server.shutdown()


def test_rollout_endpoint_is_reachable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _server(tmp_path, monkeypatch)
    try:
        status, body = _get(server, "/v1/rollout/report")
        assert status == 200
        assert json.loads(body)["report"]["current_phase"] == 1
    finally:
        server.shutdown()


def test_console_key_is_enforced_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    This view exposes every recorded action. When a key is set it is required;
    without one the routes are open like the rest of the decision profile, which
    is why the port must not be public.
    """
    import urllib.error  # noqa: F401 - imported for _get's except clause

    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "s3cret")
    server = _server(tmp_path, monkeypatch)
    try:
        assert _get(server, "/v1/decisions")[0] == 401
        assert _get(server, "/v1/rollout/report")[0] == 401

        status, _ = _get(server, "/v1/decisions", {"X-AETHERYA-Console-Key": "s3cret"})
        assert status == 200

        assert _get(server, "/v1/decisions", {"X-AETHERYA-Console-Key": "wrong"})[0] == 401
    finally:
        server.shutdown()


def test_console_page_is_not_key_gated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The shell is inert HTML; the data behind it is what the key protects."""
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "s3cret")
    server = _server(tmp_path, monkeypatch)
    try:
        assert _get(server, "/")[0] == 200
    finally:
        server.shutdown()


def test_console_routes_fail_when_the_api_is_not_configured() -> None:
    """Defensive: the handler must answer rather than raise if wiring is missing."""
    import io

    from aetherya.api_server import AetheryaHTTPRequestHandler

    class _Bare(AetheryaHTTPRequestHandler):
        def __init__(self) -> None:  # noqa: D107
            self.api = None
            self.command = "GET"
            self.path = "/v1/decisions"
            self.headers = {}  # type: ignore[assignment]
            self.sent: list[tuple[int, dict[str, Any]]] = []
            self.wfile = io.BytesIO()

        def _send_json(self, status: int, body: dict[str, Any]) -> None:  # type: ignore[override]
            self.sent.append((status, body))

    handler = _Bare()
    handler._handle_request()  # noqa: SLF001
    assert handler.sent[0][0] == 500
