from __future__ import annotations

import io
import json
from pathlib import Path
from typing import cast

import pytest
import yaml

from aetherya.api import AetheryaAPI, APISettings
from aetherya.api_server import (
    AetheryaHTTPRequestHandler,
    RequestTooLargeError,
    _build_handler,
    _dashboard_html,
    build_server,
    main,
    serve_api,
)


def _write_policy(tmp_path: Path, mutate) -> Path:  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _make_api(tmp_path: Path) -> AetheryaAPI:
    policy_path = _write_policy(tmp_path, lambda data: None)
    return AetheryaAPI(
        APISettings(
            policy_path=policy_path,
            audit_path=tmp_path / "decisions.jsonl",
        )
    )


def test_handler_send_json_writes_status_headers_and_body() -> None:
    class FakeHandler:
        def __init__(self) -> None:
            self.status: int | None = None
            self.headers: list[tuple[str, str]] = []
            self.ended = False
            self.wfile = io.BytesIO()

        def send_response(self, status: int) -> None:
            self.status = status

        def send_header(self, key: str, value: str) -> None:
            self.headers.append((key, value))

        def end_headers(self) -> None:
            self.ended = True

    fake = FakeHandler()
    AetheryaHTTPRequestHandler._send_json(fake, 201, {"ok": True})  # noqa: SLF001

    assert fake.status == 201
    assert ("Content-Type", "application/json; charset=utf-8") in fake.headers
    assert any(k == "Content-Length" for k, _ in fake.headers)
    assert fake.ended is True
    assert json.loads(fake.wfile.getvalue().decode("utf-8")) == {"ok": True}

    fake_html = FakeHandler()
    AetheryaHTTPRequestHandler._send_html(fake_html, 200, "<h1>x</h1>")  # noqa: SLF001
    assert fake_html.status == 200
    assert ("Content-Type", "text/html; charset=utf-8") in fake_html.headers
    assert fake_html.ended is True
    assert fake_html.wfile.getvalue().decode("utf-8") == "<h1>x</h1>"


def test_dashboard_template_contains_controls() -> None:
    html = _dashboard_html()
    assert "AETHERYA API Dashboard" in html
    assert "/v1/decide" in html
    assert "/v1/audit/verify" in html
    assert "/v1/confirmation/sign" in html
    assert "/v1/confirmation/verify" in html
    assert "candidate_response" in html


def test_handler_parse_json_body_branches() -> None:
    class FakeHandler:
        def __init__(self, content_length: str, raw: bytes, max_body_bytes: int = 64):
            self.headers = {"Content-Length": content_length}
            self.rfile = io.BytesIO(raw)
            self.max_body_bytes = max_body_bytes

    empty_missing = FakeHandler("", b"")
    assert AetheryaHTTPRequestHandler._parse_json_body(empty_missing) == {}  # noqa: SLF001

    empty_zero = FakeHandler("0", b"")
    assert AetheryaHTTPRequestHandler._parse_json_body(empty_zero) == {}  # noqa: SLF001

    valid = FakeHandler("17", b'{"raw_input":"x"}')
    assert AetheryaHTTPRequestHandler._parse_json_body(valid) == {"raw_input": "x"}  # noqa: SLF001

    empty_read = FakeHandler("1", b"")
    assert AetheryaHTTPRequestHandler._parse_json_body(empty_read) == {}  # noqa: SLF001

    too_large = FakeHandler("100", b"{}", max_body_bytes=8)
    with pytest.raises(RequestTooLargeError):
        AetheryaHTTPRequestHandler._parse_json_body(too_large)  # noqa: SLF001

    invalid_length = FakeHandler("nope", b"")
    with pytest.raises(ValueError, match="invalid Content-Length"):
        AetheryaHTTPRequestHandler._parse_json_body(invalid_length)  # noqa: SLF001

    negative_length = FakeHandler("-1", b"")
    with pytest.raises(ValueError, match="invalid Content-Length"):
        AetheryaHTTPRequestHandler._parse_json_body(negative_length)  # noqa: SLF001

    bad_utf8 = FakeHandler("1", b"\xff")
    with pytest.raises(ValueError, match="utf-8"):
        AetheryaHTTPRequestHandler._parse_json_body(bad_utf8)  # noqa: SLF001

    bad_json = FakeHandler("1", b"{")
    with pytest.raises(ValueError, match="valid JSON"):
        AetheryaHTTPRequestHandler._parse_json_body(bad_json)  # noqa: SLF001

    non_object = FakeHandler("2", b"[]")
    with pytest.raises(ValueError, match="JSON object"):
        AetheryaHTTPRequestHandler._parse_json_body(non_object)  # noqa: SLF001


def test_handler_handle_request_branches(tmp_path: Path) -> None:
    api = _make_api(tmp_path)

    class FakeHandler:
        def __init__(
            self,
            *,
            method: str,
            path: str,
            parse_result: dict | None = None,
            parse_error: Exception | None = None,
            service: AetheryaAPI | None = api,
        ):
            self.command = method
            self.path = path
            self._parse_result = parse_result or {}
            self._parse_error = parse_error
            self.api = service
            self.headers = {}
            self.client_address = ("127.0.0.1", 18080)
            self.sent: list[tuple[int, dict]] = []
            self.sent_html: list[tuple[int, str]] = []

        def _parse_json_body(self) -> dict:
            if self._parse_error is not None:
                raise self._parse_error
            return self._parse_result

        def _send_json(self, status: int, payload: dict) -> None:
            self.sent.append((status, payload))

        def _send_html(self, status: int, html: str) -> None:
            self.sent_html.append((status, html))

    dashboard = FakeHandler(method="GET", path="/")
    AetheryaHTTPRequestHandler._handle_request(dashboard)  # noqa: SLF001
    assert dashboard.sent_html[0][0] == 200
    assert "AETHERYA API Dashboard" in dashboard.sent_html[0][1]

    get_ok = FakeHandler(method="GET", path="/health")
    AetheryaHTTPRequestHandler._handle_request(get_ok)  # noqa: SLF001
    assert get_ok.sent[0][0] == 200
    assert get_ok.sent[0][1]["ok"] is True

    post_ok = FakeHandler(
        method="POST",
        path="/v1/decide",
        parse_result={"raw_input": "help user"},
    )
    AetheryaHTTPRequestHandler._handle_request(post_ok)  # noqa: SLF001
    assert post_ok.sent[0][0] == 200
    assert post_ok.sent[0][1]["ok"] is True

    post_value_error = FakeHandler(
        method="POST",
        path="/v1/decide",
        parse_error=ValueError("bad json"),
    )
    AetheryaHTTPRequestHandler._handle_request(post_value_error)  # noqa: SLF001
    assert post_value_error.sent[0][0] == 400
    assert post_value_error.sent[0][1]["ok"] is False

    post_too_large = FakeHandler(
        method="POST",
        path="/v1/decide",
        parse_error=RequestTooLargeError("too large"),
    )
    AetheryaHTTPRequestHandler._handle_request(post_too_large)  # noqa: SLF001
    assert post_too_large.sent[0][0] == 413
    assert post_too_large.sent[0][1]["ok"] is False

    service_missing = FakeHandler(method="GET", path="/health", service=None)
    AetheryaHTTPRequestHandler._handle_request(service_missing)  # noqa: SLF001
    assert service_missing.sent[0][0] == 500
    assert "not configured" in service_missing.sent[0][1]["error"]

    missing_route = FakeHandler(method="GET", path="/missing")
    AetheryaHTTPRequestHandler._handle_request(missing_route)  # noqa: SLF001
    assert missing_route.sent[0][0] == 404
    assert missing_route.sent[0][1]["ok"] is False


def test_handler_do_methods_and_log_message_branch() -> None:
    class FakeHandler:
        def __init__(self) -> None:
            self.calls = 0

        def _handle_request(self) -> None:
            self.calls += 1

    fake = FakeHandler()
    AetheryaHTTPRequestHandler.do_GET(fake)  # noqa: N802
    AetheryaHTTPRequestHandler.do_POST(fake)  # noqa: N802
    assert fake.calls == 2
    assert AetheryaHTTPRequestHandler.log_message(fake, "x") is None


def test_build_handler_and_build_server_wiring(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import aetherya.api_server as api_server

    api = _make_api(tmp_path)
    handler = _build_handler(api, max_body_bytes=1234)
    assert handler.api is api
    assert handler.max_body_bytes == 1234

    captured: dict[str, object] = {}

    class FakeThreadingHTTPServer:
        def __init__(self, address, request_handler) -> None:  # noqa: ANN001
            captured["address"] = address
            captured["request_handler"] = request_handler

    monkeypatch.setattr(api_server, "ThreadingHTTPServer", FakeThreadingHTTPServer)
    server = build_server("127.0.0.1", 9090, api=api, max_body_bytes=77)
    assert isinstance(server, FakeThreadingHTTPServer)
    assert captured["address"] == ("127.0.0.1", 9090)
    bound_handler = cast(type[AetheryaHTTPRequestHandler], captured["request_handler"])
    assert bound_handler.api is api
    assert bound_handler.max_body_bytes == 77


def test_serve_api_closes_server_on_success_and_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import aetherya.api_server as api_server

    policy_path = _write_policy(tmp_path, lambda data: None)
    audit_path = tmp_path / "decisions.jsonl"
    constitution_path = None

    class FakeServer:
        def __init__(self, should_raise: bool) -> None:
            self.should_raise = should_raise
            self.closed = False

        def serve_forever(self) -> None:
            if self.should_raise:
                raise RuntimeError("serve failed")

        def server_close(self) -> None:
            self.closed = True

    server_ok = FakeServer(should_raise=False)
    monkeypatch.setattr(api_server, "build_server", lambda **kwargs: server_ok)
    serve_api(
        host="127.0.0.1",
        port=8080,
        policy_path=policy_path,
        audit_path=audit_path,
        constitution_path=constitution_path,
        default_actor="robert",
        max_body_bytes=1024,
    )
    assert server_ok.closed is True

    server_boom = FakeServer(should_raise=True)
    monkeypatch.setattr(api_server, "build_server", lambda **kwargs: server_boom)
    with pytest.raises(RuntimeError, match="serve failed"):
        serve_api(
            host="127.0.0.1",
            port=8080,
            policy_path=policy_path,
            audit_path=audit_path,
            constitution_path=constitution_path,
            default_actor="robert",
            max_body_bytes=1024,
        )
    assert server_boom.closed is True


def test_api_server_main_argument_and_error_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import aetherya.api_server as api_server

    captured: dict[str, object] = {}

    def fake_serve_api(**kwargs) -> None:  # noqa: ANN003
        captured.update(kwargs)

    monkeypatch.setattr(api_server, "serve_api", fake_serve_api)
    status_ok = main(
        [
            "--host",
            "127.0.0.1",
            "--port",
            "18080",
            "--policy-path",
            "config/policy.yaml",
            "--audit-path",
            "",
            "--constitution-path",
            "",
            "--default-actor",
            "robert",
            "--max-body-bytes",
            "1024",
        ]
    )
    assert status_ok == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 18080
    assert captured["audit_path"] is None
    assert captured["constitution_path"] is None
    assert captured["max_body_bytes"] == 1024
    assert captured["service_name"] == "aetherya-api"
    assert captured["enable_decide_routes"] is True
    assert captured["enable_audit_routes"] is True
    assert captured["enable_approval_routes"] is True

    captured.clear()
    status_decision = main(["--service-mode", "decision"])
    assert status_decision == 0
    assert captured["service_name"] == "aetherya-decision"
    assert captured["enable_decide_routes"] is True
    assert captured["enable_audit_routes"] is True
    assert captured["enable_approval_routes"] is False

    captured.clear()
    status_approvals = main(["--service-mode", "approvals"])
    assert status_approvals == 0
    assert captured["service_name"] == "aetherya-approvals"
    assert captured["enable_decide_routes"] is False
    assert captured["enable_audit_routes"] is False
    assert captured["enable_approval_routes"] is True

    status_bad_port = main(["--port", "0"])
    assert status_bad_port == 1
    assert "port must be between 1 and 65535" in capsys.readouterr().err

    status_bad_max = main(["--max-body-bytes", "0"])
    assert status_bad_max == 1
    assert "max-body-bytes must be > 0" in capsys.readouterr().err

    def boom(**kwargs) -> None:  # noqa: ANN003
        raise RuntimeError("serve failure")

    monkeypatch.setattr(api_server, "serve_api", boom)
    status_boom = main([])
    assert status_boom == 1
    assert "serve failure" in capsys.readouterr().err

    def ctrl_c(**kwargs) -> None:  # noqa: ANN003
        raise KeyboardInterrupt()

    monkeypatch.setattr(api_server, "serve_api", ctrl_c)
    assert main([]) == 0


def test_split_server_wrappers_delegate_service_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aetherya.api_server as api_server
    import aetherya.approvals_server as approvals_server
    import aetherya.decision_server as decision_server

    captured_argv: list[str] = []

    def fake_main(argv):  # noqa: ANN001, ANN202
        captured_argv[:] = list(argv)
        return 0

    monkeypatch.setattr(api_server, "main", fake_main)

    assert decision_server.main([]) == 0
    assert captured_argv[:2] == ["--service-mode", "decision"]
    assert decision_server.main(["--port", "19090"]) == 0
    assert captured_argv[:4] == ["--service-mode", "decision", "--port", "19090"]

    assert approvals_server.main([]) == 0
    assert captured_argv[:4] == ["--service-mode", "approvals", "--port", "8081"]
    assert approvals_server.main(["--host", "0.0.0.0"]) == 0
    assert captured_argv[:6] == [
        "--service-mode",
        "approvals",
        "--port",
        "8081",
        "--host",
        "0.0.0.0",
    ]
