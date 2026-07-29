from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
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


def test_rollout_treats_a_missing_audit_file_as_an_empty_window(tmp_path: Path) -> None:
    """
    Changed deliberately: this used to 400. A fresh volume has no audit file, so
    a healthy first boot rendered as an error in the console. The CLI still
    fails on it — see test_the_cli_still_fails_on_a_missing_audit_file.
    """
    code, body = _api(tmp_path, tmp_path / "nope.jsonl").rollout()
    assert code == 200
    assert body["report"]["window"]["total_decisions"] == 0


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


def _post(server: Any, path: str, payload: Any, headers: dict[str, str] | None = None) -> Any:
    import urllib.request

    request = urllib.request.Request(  # noqa: S310
        f"http://127.0.0.1:{server.server_port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
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


# ---------------------------------------------------------------------------
# Review queue — the console's only write
# ---------------------------------------------------------------------------


def _api_with_reviews(tmp_path: Path, audit: Path) -> AetheryaAPI:
    return AetheryaAPI(
        APISettings(
            policy_path=Path("config/policy.yaml"),
            audit_path=audit,
            review_path=tmp_path / "reviews.jsonl",
        )
    )


def _hard_deny_ids(audit: Path) -> list[str]:
    ids: list[str] = []
    for line in audit.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("decision", {}).get("state") == "hard_deny":
            ids.append(event["event_id"])
    return ids


def test_a_review_is_recorded_and_reaches_the_report(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    api = _api_with_reviews(tmp_path, audit)
    event_id = _hard_deny_ids(audit)[0]

    code, body = api.record_review(
        {"event_id": event_id, "verdict": "true_positive", "reviewer": "robert"}
    )
    assert code == 200
    assert body["review"]["verdict"] == "true_positive"

    events = api.rollout()[1]["report"]["hard_deny_events"]
    assert events[0]["review"]["reviewer"] == "robert"


def test_reviewing_an_unknown_event_is_refused(tmp_path: Path) -> None:
    """
    A verdict on an id that is not in the trail would be recorded, counted by
    nothing, and leave the operator believing they had reviewed something.
    """
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])

    code, body = _api_with_reviews(tmp_path, audit).record_review(
        {"event_id": "made-up", "verdict": "true_positive", "reviewer": "robert"}
    )
    assert code == 400
    assert "no audit event" in body["error"]


def test_reviewing_a_non_hard_deny_event_is_refused(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow")])
    allow_id = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])["event_id"]

    code, body = _api_with_reviews(tmp_path, audit).record_review(
        {"event_id": allow_id, "verdict": "true_positive", "reviewer": "robert"}
    )
    assert code == 400
    assert "not `hard_deny`" in body["error"]


@pytest.mark.parametrize(
    "payload",
    [
        {"verdict": "true_positive", "reviewer": "r"},
        {"event_id": "x", "reviewer": "r"},
        {"event_id": "x", "verdict": "true_positive"},
        {"event_id": "x", "verdict": "nonsense", "reviewer": "r"},
        [],
    ],
)
def test_malformed_review_payloads_are_rejected(tmp_path: Path, payload: Any) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    assert _api_with_reviews(tmp_path, audit).record_review(payload)[0] == 400


def test_reviews_are_listed_newest_first(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny"), ("b", "hard_deny")])
    api = _api_with_reviews(tmp_path, audit)
    ids = _hard_deny_ids(audit)

    api.record_review({"event_id": ids[0], "verdict": "true_positive", "reviewer": "first"})
    api.record_review({"event_id": ids[1], "verdict": "true_positive", "reviewer": "second"})

    code, body = api.reviews()
    assert code == 200
    assert [r["reviewer"] for r in body["reviews"]] == ["second", "first"]


def test_review_routes_fail_when_the_store_is_disabled(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    api = AetheryaAPI(APISettings(audit_path=audit, review_path=None))

    assert (
        api.record_review({"event_id": "x", "verdict": "true_positive", "reviewer": "r"})[0] == 400
    )
    assert api.reviews()[0] == 400


def test_recording_a_review_requires_a_configured_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Without a key the verdict carries a reviewer name nobody had to prove,
    which is worse than having no attribution at all. Reads stay open; this
    write does not.
    """
    monkeypatch.delenv("AETHERYA_CONSOLE_API_KEY", raising=False)
    server = _server(tmp_path, monkeypatch)
    try:
        status, body = _post(server, "/v1/reviews", {"event_id": "x"})
        assert status == 503
        assert "AETHERYA_CONSOLE_API_KEY" in json.loads(body)["error"]
    finally:
        server.shutdown()


def test_recording_a_review_over_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "s3cret")
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    event_id = _hard_deny_ids(audit)[0]

    import threading

    from aetherya.api_server import build_server

    api = _api_with_reviews(tmp_path, audit)
    server = build_server(host="127.0.0.1", port=0, api=api, max_body_bytes=65536)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        payload = {"event_id": event_id, "verdict": "true_positive", "reviewer": "robert"}
        assert _post(server, "/v1/reviews", payload)[0] == 401
        status, body = _post(server, "/v1/reviews", payload, {"X-AETHERYA-Console-Key": "s3cret"})
        assert status == 200
        assert json.loads(body)["review"]["reviewer"] == "robert"

        status, body = _get(server, "/v1/reviews", {"X-AETHERYA-Console-Key": "s3cret"})
        assert json.loads(body)["count"] == 1
    finally:
        server.shutdown()


def test_an_invalid_review_body_is_a_400(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "s3cret")
    server = _server(tmp_path, monkeypatch)
    try:
        import urllib.request

        url = f"http://127.0.0.1:{server.server_port}/v1/reviews"
        request = urllib.request.Request(  # noqa: S310
            url,
            data=b"{broken",
            method="POST",
            headers={"X-AETHERYA-Console-Key": "s3cret"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)  # noqa: S310
        assert exc.value.code == 400
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# The page must actually offer the buttons
# ---------------------------------------------------------------------------


def test_the_console_renders_verdict_buttons() -> None:
    html = console_html()
    assert 'data-verdict="true_positive"' in html
    assert 'data-verdict="false_positive"' in html
    assert '"/v1/reviews"' in html


def test_the_console_requires_a_note_for_a_false_positive() -> None:
    """Mirrors the store's rule so the UI cannot submit something it will reject."""
    html = console_html()
    assert "if(!note.trim()){ return; }" in html


def test_reviewing_without_an_audit_trail_is_refused(tmp_path: Path) -> None:
    api = AetheryaAPI(APISettings(audit_path=None, review_path=tmp_path / "r.jsonl"))
    code, body = api.record_review({"event_id": "x", "verdict": "true_positive", "reviewer": "r"})
    assert code == 400
    assert "audit_path is disabled" in body["error"]


def test_reviewing_against_a_missing_audit_file_is_refused(tmp_path: Path) -> None:
    api = AetheryaAPI(
        APISettings(audit_path=tmp_path / "gone.jsonl", review_path=tmp_path / "r.jsonl")
    )
    assert (
        api.record_review({"event_id": "x", "verdict": "true_positive", "reviewer": "r"})[0] == 400
    )


def test_a_malformed_audit_line_does_not_break_the_event_lookup(tmp_path: Path) -> None:
    """The garbage sits before the target, so the scan has to survive it to find it."""
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    with audit.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
        handle.write("\n")
    _seed(audit, [("b", "hard_deny")])
    event_id = _hard_deny_ids(audit)[-1]

    api = _api_with_reviews(tmp_path, audit)
    assert (
        api.record_review({"event_id": event_id, "verdict": "true_positive", "reviewer": "r"})[0]
        == 200
    )


def test_an_event_without_a_decision_object_reports_unknown(tmp_path: Path) -> None:
    audit = tmp_path / "decisions.jsonl"
    audit.write_text(json.dumps({"event_id": "bare", "actor": "a"}) + "\n", encoding="utf-8")

    code, body = _api_with_reviews(tmp_path, audit).record_review(
        {"event_id": "bare", "verdict": "true_positive", "reviewer": "r"}
    )
    assert code == 400
    assert "is `unknown`" in body["error"]


def test_the_review_route_fails_when_the_api_is_not_configured() -> None:
    import io

    from aetherya.api_server import AetheryaHTTPRequestHandler

    class _Bare(AetheryaHTTPRequestHandler):
        def __init__(self) -> None:
            self.api = None
            self.command = "POST"
            self.path = "/v1/reviews"
            self.headers = {}  # type: ignore[assignment]
            self.sent: list[tuple[int, dict[str, Any]]] = []
            self.wfile = io.BytesIO()

        def _send_json(self, status: int, body: dict[str, Any]) -> None:  # type: ignore[override]
            self.sent.append((status, body))

    handler = _Bare()
    handler._handle_request()  # noqa: SLF001
    assert handler.sent[0][0] == 500


def test_the_console_sends_the_key_on_reads_too() -> None:
    """
    Regression: the key was only sent on writes. With AETHERYA_CONSOLE_API_KEY
    set — the normal deployment — every read 401'd and the page rendered empty
    while the server looked healthy.
    """
    html = console_html()
    get_fn = html.split("async function get(url")[1].split("}")[0]
    assert "X-AETHERYA-Console-Key" in get_fn


def test_the_console_reports_being_locked_rather_than_hanging() -> None:
    """A page stuck on `loading…` sends you to the server logs for nothing."""
    html = console_html()
    assert "Locked — the console key was rejected." in html
    assert "function locked(" in html


def test_the_console_reads_the_key_from_one_place() -> None:
    """Two copies of the key drift; the write path would authenticate and the
    read path would not, which is exactly the bug above."""
    assert console_html().count("localStorage.getItem(KEY)") == 1


def test_the_console_page_is_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Regression: the page ships inside the engine and changes with every upgrade
    while its URL does not. Cached, an operator runs the previous console
    against the new API and gets a page that hangs instead of one that looks
    out of date.
    """
    import urllib.request

    server = _server(tmp_path, monkeypatch)
    try:
        with urllib.request.urlopen(  # noqa: S310
            f"http://127.0.0.1:{server.server_port}/", timeout=5
        ) as response:
            assert "no-store" in response.headers.get("Cache-Control", "")
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# The page has to parse, not merely contain the right substrings
# ---------------------------------------------------------------------------


def test_the_console_template_contains_no_python_escape_sequences() -> None:
    r"""
    Regression, and the reason every other test here missed it.

    The console's JS lives inside a Python string literal. A `\n` written for
    JavaScript is consumed by Python and emitted as a real newline, which splits
    the JS string it was in and stops the *entire script* from parsing. Nothing
    on the page runs, every panel sits on "loading…", and the server reports
    healthy the whole time — so it reads as a server or cache problem.

    Every other console test asserted substrings, which all still matched.
    Checking the source is what catches this: any of these escapes appearing
    literally in the template is meant for the browser and will never reach it.
    Use a JS template literal with a real line break instead.
    """
    source = Path("src/aetherya/console.py").read_text(encoding="utf-8")
    template = source[source.index('"""') :]

    offenders = [
        (line_no, line.strip())
        for line_no, line in enumerate(template.splitlines(), start=1)
        for escape in ("\\n", "\\t", "\\r", "\\x")
        if escape in line
    ]
    assert offenders == [], f"Python escape sequences in the JS template: {offenders}"


def test_the_console_javascript_parses() -> None:
    """
    The only reliable check here is a real parser.

    Two attempts at a pure-Python heuristic both produced false positives on
    lines the page legitimately contains — `/[&<>"\']/g`, and `\'"\':"&quot;"` —
    so counting quotes is out. Node is preinstalled on CI runners, which is where
    this needs to hold; it skips on a machine without it, and the source-level
    escape test above still runs everywhere.

    Twice now a syntax error in this template stopped the entire page from
    running while every substring assertion kept passing.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; the escape-sequence test covers the same class")

    js = console_html().split("<script>")[1].split("</script>")[0]
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
        handle.write(js)
        script = handle.name
    try:
        result = subprocess.run(  # noqa: S603
            [node, "--check", script], capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stderr
    finally:
        Path(script).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# A console field must not be able to write a secret into the audit trail
# ---------------------------------------------------------------------------


def test_the_console_key_cannot_be_recorded_as_a_reviewer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Regression, hit for real: the console asks for a key and then, in an
    identical prompt, for a name. Pasting the key into the name wrote the
    credential in plaintext into the audit trail — which is exported, mirrored
    and archived, so it cannot be taken back out.
    """
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "local-dev-console-key-replace-me")
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    event_id = _hard_deny_ids(audit)[0]

    code, body = _api_with_reviews(tmp_path, audit).record_review(
        {
            "event_id": event_id,
            "verdict": "true_positive",
            "reviewer": "local-dev-console-key-replace-me",
        }
    )
    assert code == 400
    assert "contains a credential" in body["error"]


def test_a_credential_embedded_in_a_note_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AETHERYA_CONFIRMATION_HMAC_KEY", "super-secret-hmac-value")
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    event_id = _hard_deny_ids(audit)[0]

    code, body = _api_with_reviews(tmp_path, audit).record_review(
        {
            "event_id": event_id,
            "verdict": "false_positive",
            "reviewer": "robert",
            "note": "pasted by mistake: super-secret-hmac-value",
        }
    )
    assert code == 400
    assert "note contains a credential" in body["error"]


def test_an_ordinary_name_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "local-dev-console-key-replace-me")
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    event_id = _hard_deny_ids(audit)[0]

    code, _ = _api_with_reviews(tmp_path, audit).record_review(
        {"event_id": event_id, "verdict": "true_positive", "reviewer": "robert"}
    )
    assert code == 200


def test_a_short_secret_does_not_reject_ordinary_prose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A two-character key would match half the alphabet. Below a real key's
    length the check would block legitimate reviews, which is worse than the
    mistake it prevents.
    """
    monkeypatch.setenv("AETHERYA_CONSOLE_API_KEY", "ab")
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "hard_deny")])
    event_id = _hard_deny_ids(audit)[0]

    code, _ = _api_with_reviews(tmp_path, audit).record_review(
        {"event_id": event_id, "verdict": "true_positive", "reviewer": "abigail"}
    )
    assert code == 200


def test_the_console_refuses_to_send_the_key_as_a_name() -> None:
    html = console_html()
    assert "not the console key" in html
    assert "reviewer === consoleKey()" in html


def test_a_rejected_key_does_not_reprompt_on_every_poll() -> None:
    """
    Regression: `get()` prompted on 401 and the page polls every 10s, so a wrong
    key produced an inescapable dialog every few seconds. Only refresh() decides
    when to ask, and it pauses polling until the operator answers.
    """
    html = console_html()
    get_body = html.split("async function get(url)")[1].split("\n}")[0]
    assert "prompt(" not in get_body
    assert "if(paused) return;" in html
    assert "paused = true;" in html


def test_a_locked_console_offers_a_way_back_in() -> None:
    """A dead end with no button is indistinguishable from a broken page."""
    html = console_html()
    assert "Enter console key" in html
    assert "the console key was rejected" in html.lower()
    assert "function unlock()" in html


def test_the_console_renders_on_a_deployment_that_has_decided_nothing(tmp_path: Path) -> None:
    """
    Regression: a fresh volume has no audit file, and the report raised, so the
    console showed an error on a perfectly healthy first boot. The feed already
    treated this as empty rather than broken; the report now agrees.
    """
    api = _api_with_reviews(tmp_path, tmp_path / "not-yet.jsonl")
    code, body = api.rollout()

    assert code == 200
    assert body["report"]["window"]["total_decisions"] == 0
    assert body["report"]["hard_deny_events"] == []
    assert api.decisions()[0] == 200


def test_the_cli_still_fails_on_a_missing_audit_file(tmp_path: Path) -> None:
    """Asking the CLI to measure a file that is not there is a bad argument."""
    from aetherya.rollout_report import build_report

    with pytest.raises(ValueError, match="audit file not found"):
        build_report(tmp_path / "nope.jsonl")


def test_a_fresh_deployment_reports_an_intact_chain(tmp_path: Path) -> None:
    """
    Regression: `verify_audit_file` raises on a missing file, so `chain_intact`
    said "investigate before advancing" on a deployment that had decided
    nothing. A chain of zero events is vacuously intact — there is nothing that
    could be inconsistent, and nothing to investigate.
    """
    report = _api_with_reviews(tmp_path, tmp_path / "not-yet.jsonl").rollout()[1]["report"]
    chain = next(c for c in report["criteria"] if c["name"] == "chain_intact")

    assert chain["passed"] is True
    assert report["chain"]["detail"] is None


def test_a_real_chain_break_is_still_reported(tmp_path: Path) -> None:
    """The relaxation above must not swallow a genuine tampering finding."""
    audit = tmp_path / "decisions.jsonl"
    _seed(audit, [("a", "allow"), ("b", "allow")])
    lines = audit.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["actor"] = "someone-else"
    audit.write_text(
        json.dumps(tampered) + "\n" + lines[1] + "\n",
        encoding="utf-8",
    )

    report = _api_with_reviews(tmp_path, audit).rollout()[1]["report"]
    chain = next(c for c in report["criteria"] if c["name"] == "chain_intact")
    assert chain["passed"] is False


def test_the_empty_feed_says_what_to_do_about_it() -> None:
    """An empty state that only says "empty" leaves you guessing whether the
    service is broken or idle."""
    html = console_html()
    assert "waiting for traffic" in html
    assert "aetherya decide" in html
