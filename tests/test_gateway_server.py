from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.gateway import AetheryaGateway, GatewaySettings, UpstreamError
from aetherya.gateway_server import (
    build_gateway,
    build_gateway_server,
    check_actor_is_known,
    main,
)

POLICY = Path("config/policy.yaml")


class _FakeOpenAI:
    def __init__(self, response: Any) -> None:
        self._response = response
        self.chat = self  # type: ignore[assignment]
        self.completions = self  # type: ignore[assignment]

    def create(self, **kwargs: Any) -> Any:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _completion(tool_calls: list[dict[str, Any]] | None = None, content: str | None = None) -> Any:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-4o-mini",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
    }


def _gateway(response: Any, phase: int = 2) -> AetheryaGateway:
    return AetheryaGateway(
        GatewaySettings(provider="openai", model="gpt-4o-mini", actor="robert", phase=phase),
        constitution=Constitution(
            [Principle("SystemIntegrity", "x", priority=1, keywords=["rm -rf /"], risk=92)],
            use_semantic=False,
        ),
        cfg=load_policy_config(POLICY),
        upstream=_FakeOpenAI(response),
    )


@pytest.fixture
def server(request: pytest.FixtureRequest) -> Any:
    gateway = getattr(request, "param", None) or _gateway(_completion(content="hi"))
    srv = build_gateway_server("127.0.0.1", 0, gateway=gateway)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _request(srv: Any, path: str, body: Any = None, method: str = "GET") -> tuple[int, str]:
    url = f"http://127.0.0.1:{srv.server_port}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(  # noqa: S310
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


# ---------------------------------------------------------------------------
# The surface an agent runtime probes before it will use a provider
# ---------------------------------------------------------------------------


def test_health_reports_the_provider_and_phase(server: Any) -> None:
    status, body = _request(server, "/health")
    payload = json.loads(body)
    assert status == 200
    assert payload["provider"] == "openai"
    assert payload["phase_name"] == "hard_deny"


def test_the_model_list_advertises_the_configured_model(server: Any) -> None:
    """OpenClaw validates the model id against this list before it will call."""
    status, body = _request(server, "/v1/models")
    assert status == 200
    assert json.loads(body)["data"][0]["id"] == "gpt-4o-mini"


def test_both_the_prefixed_and_bare_paths_are_served(server: Any) -> None:
    """Clients differ on whether they append /v1 to a configured baseUrl."""
    assert _request(server, "/models")[0] == 200
    assert _request(server, "/chat/completions", {"messages": []}, "POST")[0] == 200


def test_a_trailing_slash_still_routes(server: Any) -> None:
    assert _request(server, "/v1/models/")[0] == 200


def test_an_unknown_path_is_a_404(server: Any) -> None:
    for method, path in [("GET", "/nope"), ("POST", "/v1/embeddings")]:
        status, body = _request(server, path, {} if method == "POST" else None, method)
        assert status == 404
        assert json.loads(body)["error"]["type"] == "not_found"


# ---------------------------------------------------------------------------
# Completions
# ---------------------------------------------------------------------------


def test_a_completion_round_trips(server: Any) -> None:
    status, body = _request(server, "/v1/chat/completions", {"messages": []}, "POST")
    assert status == 200
    assert json.loads(body)["choices"][0]["message"]["content"] == "hi"


@pytest.mark.parametrize(
    "server",
    [
        _gateway(
            _completion(
                [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {
                            "name": "shell",
                            "arguments": '{"command": "rm -rf /"}',
                        },
                    }
                ]
            )
        )
    ],
    indirect=True,
)
def test_a_refused_tool_call_does_not_reach_the_client(server: Any) -> None:
    status, body = _request(server, "/v1/chat/completions", {"messages": []}, "POST")
    payload = json.loads(body)
    assert status == 200
    assert "tool_calls" not in payload["choices"][0]["message"]
    assert payload["aetherya"]["refused"] == 1


def test_a_streaming_request_gets_sse_frames_terminated_by_done(server: Any) -> None:
    status, body = _request(
        server, "/v1/chat/completions", {"messages": [], "stream": True}, "POST"
    )
    assert status == 200
    assert body.rstrip().endswith("data: [DONE]")
    frames = [
        json.loads(line[6:])
        for line in body.splitlines()
        if line.startswith("data: ") and line != "data: [DONE]"
    ]
    assert frames[-1]["choices"][0]["finish_reason"] == "stop"


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


def test_an_invalid_json_body_is_a_400(server: Any) -> None:
    url = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
    req = urllib.request.Request(url, data=b"{oops", method="POST")  # noqa: S310
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)  # noqa: S310
    assert exc.value.code == 400


def test_a_non_object_body_is_a_400(server: Any) -> None:
    status, body = _request(server, "/v1/chat/completions", [1, 2, 3], "POST")
    assert status == 400
    assert "JSON object" in json.loads(body)["error"]["message"]


def test_an_oversized_body_is_rejected_before_it_is_read(server: Any) -> None:
    url = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
    req = urllib.request.Request(  # noqa: S310
        url, data=b"{}", method="POST", headers={"Content-Length": "99999999"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)  # noqa: S310
    assert exc.value.code == 413


@pytest.mark.parametrize("server", [_gateway(RuntimeError("connection reset"))], indirect=True)
def test_an_upstream_failure_is_a_502_not_a_500(server: Any) -> None:
    """
    An agent that cannot tell the boundary failing from the model failing will
    retry the wrong one. 502 says the hop beyond us broke.
    """
    status, body = _request(server, "/v1/chat/completions", {"messages": []}, "POST")
    assert status == 502
    assert json.loads(body)["error"]["type"] == "upstream_error"


def test_an_internal_failure_is_a_500(server: Any) -> None:
    class _Exploding(AetheryaGateway):
        def complete(self, body: dict[str, Any]) -> dict[str, Any]:
            raise ZeroDivisionError("boom")

    srv = build_gateway_server(
        "127.0.0.1",
        0,
        gateway=_Exploding(
            GatewaySettings(),
            constitution=Constitution([], use_semantic=False),
            cfg=load_policy_config(POLICY),
        ),
    )
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _request(srv, "/v1/chat/completions", {"messages": []}, "POST")
        assert status == 500
        assert "ZeroDivisionError" in json.loads(body)["error"]["message"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_unconfigured_handler_answers_rather_than_raising() -> None:
    """Defensive: a bare handler must return 500, not kill the connection."""
    import io

    from aetherya.gateway_server import GatewayHTTPRequestHandler

    class _Bare(GatewayHTTPRequestHandler):
        def __init__(self) -> None:
            self.gateway = None
            self.path = "/v1/chat/completions"
            self.headers = {}  # type: ignore[assignment]
            self.sent: list[tuple[int, dict[str, Any]]] = []
            self.wfile = io.BytesIO()

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:  # type: ignore[override]
            self.sent.append((status, payload))

    handler = _Bare()
    handler.do_POST()
    assert handler.sent[0][0] == 500

    health = _Bare()
    health.path = "/health"
    health.do_GET()
    assert health.sent[0][1]["ok"] is False


def test_an_invalid_content_length_is_a_400() -> None:
    import io

    from aetherya.gateway_server import GatewayHTTPRequestHandler

    class _Bad(GatewayHTTPRequestHandler):
        def __init__(self) -> None:
            self.gateway = _gateway(_completion(content="hi"))
            self.path = "/v1/chat/completions"
            self.headers = {"Content-Length": "abc"}  # type: ignore[assignment]
            self.sent: list[tuple[int, dict[str, Any]]] = []
            self.wfile = io.BytesIO()

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:  # type: ignore[override]
            self.sent.append((status, payload))

    handler = _Bad()
    handler.do_POST()
    assert handler.sent[0][0] == 400


def test_request_logging_goes_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    import io

    from aetherya.gateway_server import GatewayHTTPRequestHandler

    class _Quiet(GatewayHTTPRequestHandler):
        def __init__(self) -> None:
            self.wfile = io.BytesIO()

        def address_string(self) -> str:
            return "1.2.3.4"

    _Quiet().log_message("%s %s", "GET", "/health")
    assert "1.2.3.4 GET /health" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------


def test_an_unknown_actor_is_fatal_at_phase_3() -> None:
    cfg = load_policy_config(POLICY)
    with pytest.raises(ValueError, match="not in capability_matrix"):
        check_actor_is_known(cfg.capability_matrix, "openclaw", 3)


def test_an_unknown_actor_only_warns_at_phase_1(capsys: pytest.CaptureFixture[str]) -> None:
    """
    Phase 1 does not enforce `deny`, so an unknown actor is harmless there —
    but it is the thing that will brick phase 3, so say it early.
    """
    cfg = load_policy_config(POLICY)
    check_actor_is_known(cfg.capability_matrix, "openclaw", 1)
    assert "will be denied" in capsys.readouterr().err


def test_a_known_actor_passes_at_every_phase(capsys: pytest.CaptureFixture[str]) -> None:
    cfg = load_policy_config(POLICY)
    for phase in (1, 2, 3):
        check_actor_is_known(cfg.capability_matrix, "robert", phase)
    assert capsys.readouterr().err == ""


def test_the_check_is_skipped_when_the_matrix_would_allow_anyway() -> None:
    class _Matrix:
        enabled = False
        default_allow = False
        actors: dict[str, Any] = {}

    check_actor_is_known(_Matrix(), "anyone", 3)

    class _Open(_Matrix):
        enabled = True
        default_allow = True

    check_actor_is_known(_Open(), "anyone", 3)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_a_gateway_is_built_from_the_policy_on_disk(tmp_path: Path) -> None:
    gateway = build_gateway(
        policy_path=POLICY,
        constitution_path=None,
        audit_path=tmp_path / "decisions.jsonl",
        settings=GatewaySettings(actor="robert", phase=2),
    )
    assert gateway.phase.number == 2
    assert gateway.audit is not None


def test_a_custom_constitution_file_is_honoured(tmp_path: Path) -> None:
    path = tmp_path / "constitution.yaml"
    path.write_text(
        "principles:\n"
        "  - name: OnlyRule\n"
        "    description: the only rule\n"
        "    priority: 1\n"
        "    keywords: ['forbidden']\n"
        "    risk: 99\n",
        encoding="utf-8",
    )
    gateway = build_gateway(
        policy_path=POLICY,
        constitution_path=path,
        audit_path=None,
        settings=GatewaySettings(actor="robert"),
    )
    assert [p.name for p in gateway.constitution.principles] == ["OnlyRule"]
    assert gateway.audit is None


def test_the_cli_reports_its_configuration_and_serves(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    served: dict[str, Any] = {}

    class _Server:
        def serve_forever(self) -> None:
            served["ran"] = True
            raise KeyboardInterrupt

        def server_close(self) -> None:
            served["closed"] = True

    monkeypatch.setattr("aetherya.gateway_server.build_gateway_server", lambda *a, **k: _Server())
    code = main(
        [
            "--port",
            "0",
            "--actor",
            "robert",
            "--phase",
            "2",
            "--audit-path",
            str(tmp_path / "a.jsonl"),
        ]
    )
    assert code == 0
    assert served == {"ran": True, "closed": True}
    assert "phase 2 (hard_deny)" in capsys.readouterr().err


def test_binding_to_a_public_interface_is_warned_about(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """This process holds the upstream API key and authenticates nobody."""

    class _Server:
        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            pass

    monkeypatch.setattr("aetherya.gateway_server.build_gateway_server", lambda *a, **k: _Server())
    public = "0.0.0.0"  # noqa: S104 - the point of the test
    main(["--host", public, "--actor", "robert", "--audit-path", str(tmp_path / "a.jsonl")])
    assert "non-loopback" in capsys.readouterr().err


def test_the_phase_defaults_to_the_policy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    class _Server:
        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            pass

    monkeypatch.setattr("aetherya.gateway_server.build_gateway_server", lambda *a, **k: _Server())
    main(["--actor", "robert", "--audit-path", str(tmp_path / "a.jsonl")])
    expected = load_policy_config(POLICY).enforcement.phase
    assert f"phase {expected} " in capsys.readouterr().err


def test_the_default_provider_is_anthropic_on_opus_5(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    class _Server:
        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            pass

    monkeypatch.delenv("AETHERYA_GATEWAY_PROVIDER", raising=False)
    monkeypatch.delenv("AETHERYA_GATEWAY_MODEL", raising=False)
    monkeypatch.setattr("aetherya.gateway_server.build_gateway_server", lambda *a, **k: _Server())
    main(["--actor", "robert", "--audit-path", str(tmp_path / "a.jsonl")])
    assert "anthropic/claude-opus-5" in capsys.readouterr().err


def test_the_upstream_error_type_is_exported() -> None:
    assert issubclass(UpstreamError, RuntimeError)
