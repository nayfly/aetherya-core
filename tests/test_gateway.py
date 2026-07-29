from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aetherya.actions import ActionRequest
from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.constitution import Constitution, Principle
from aetherya.gateway import (
    AetheryaGateway,
    GatewaySettings,
    UpstreamError,
    tool_call_to_action,
)

# ---------------------------------------------------------------------------
# The upstream is faked throughout. What is under test is the boundary — which
# tool calls survive it and what the agent is told — not OpenAI's or
# Anthropic's servers. The live path needs a real key and is exercised by
# scripts/gateway_smoke.py.
# ---------------------------------------------------------------------------


def _constitution() -> Constitution:
    return Constitution(
        [
            Principle(
                "SystemIntegrity",
                "Protect critical system operations",
                priority=1,
                keywords=["rm -rf /", "mkfs", "drop table"],
                risk=92,
            )
        ],
        use_semantic=False,
    )


def _completion(tool_calls: list[dict[str, Any]] | None = None, content: str | None = None) -> Any:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }
        ],
    }


def _call(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


class _FakeOpenAI:
    """Minimal stand-in for `openai.OpenAI` shaped like the call sites use it."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.requests: list[dict[str, Any]] = []
        self.chat = self  # type: ignore[assignment]
        self.completions = self  # type: ignore[assignment]

    def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _gateway(
    upstream: Any,
    *,
    phase: int = 1,
    audit: AuditLogger | None = None,
    provider: str = "openai",
    actor: str = "openclaw",
) -> AetheryaGateway:
    return AetheryaGateway(
        GatewaySettings(provider=provider, model="gpt-4o-mini", actor=actor, phase=phase),
        constitution=_constitution(),
        cfg=load_policy_config(Path("config/policy.yaml")),
        audit=audit,
        upstream=upstream,
    )


# ---------------------------------------------------------------------------
# Tool call -> ActionRequest
# ---------------------------------------------------------------------------


def test_a_tool_call_becomes_a_structured_action() -> None:
    action = tool_call_to_action("shell", {"command": "ls -la"})
    assert action.tool == "shell"
    assert action.intent == "operate"
    assert action.parameters == {"command": "ls -la"}


def test_argument_values_reach_raw_input() -> None:
    """
    The guards read `raw_input`. A destructive command that only ever appears
    inside an argument must still be visible to them.
    """
    action = tool_call_to_action("shell", {"command": "rm -rf /"})
    assert "rm -rf /" in action.raw_input


def test_path_and_target_arguments_populate_target() -> None:
    assert tool_call_to_action("read", {"path": "/etc/shadow"}).target == "/etc/shadow"
    assert tool_call_to_action("http", {"target": "example.com"}).target == "example.com"


def test_a_tool_call_without_a_target_argument_has_no_target() -> None:
    assert tool_call_to_action("noop", {}).target is None


def test_none_arguments_are_omitted_from_raw_input() -> None:
    action = tool_call_to_action("shell", {"command": "ls", "cwd": None})
    assert action.raw_input == "shell ls"


def test_the_generated_action_is_valid() -> None:
    tool_call_to_action("shell", {"command": "ls"}).validate()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def test_malformed_arguments_are_still_gated() -> None:
    """
    Dropping unparseable arguments would silently skip the check. They are
    passed through as raw text, which is what a guard needs to see anyway.
    """
    gateway = _gateway(_FakeOpenAI(_completion()))
    gated = gateway.gate_tool_calls(
        [{"id": "c", "function": {"name": "shell", "arguments": "{not json"}}]
    )
    assert gated[0].arguments == {"_raw": "{not json"}


def test_a_destructive_command_in_malformed_arguments_is_still_caught() -> None:
    gateway = _gateway(_FakeOpenAI(_completion()), phase=2)
    gated = gateway.gate_tool_calls(
        [{"id": "c", "function": {"name": "shell", "arguments": '{"cmd": "rm -rf /"'}}]
    )
    assert gated[0].state == "hard_deny"
    assert gated[0].execute is False


def test_arguments_may_arrive_as_an_object() -> None:
    gateway = _gateway(_FakeOpenAI(_completion()))
    gated = gateway.gate_tool_calls(
        [{"id": "c", "function": {"name": "shell", "arguments": {"command": "ls"}}}]
    )
    assert gated[0].arguments == {"command": "ls"}


def test_empty_and_non_object_arguments_are_tolerated() -> None:
    gateway = _gateway(_FakeOpenAI(_completion()))
    calls = [
        {"id": "a", "function": {"name": "t", "arguments": ""}},
        {"id": "b", "function": {"name": "t", "arguments": None}},
        {"id": "c", "function": {"name": "t", "arguments": "[1, 2]"}},
    ]
    gated = gateway.gate_tool_calls(calls)
    assert gated[0].arguments == {}
    assert gated[1].arguments == {}
    assert gated[2].arguments == {"_value": [1, 2]}


# ---------------------------------------------------------------------------
# Phase behaviour
# ---------------------------------------------------------------------------


def test_phase_1_records_a_destructive_call_but_lets_it_through() -> None:
    """Shadow mode must not change what the agent does — that is its whole point."""
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "rm -rf /"})]))
    result = _gateway(upstream, phase=1).complete({"messages": []})

    assert result["choices"][0]["message"]["tool_calls"]
    trace = result["aetherya"]
    assert trace["phase"] == 1
    assert trace["refused"] == 0
    assert trace["shadow_gap"] == 1
    assert trace["gated"][0]["state"] == "hard_deny"


def test_phase_2_removes_the_refused_call() -> None:
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "rm -rf /"})]))
    result = _gateway(upstream, phase=2).complete({"messages": []})

    message = result["choices"][0]["message"]
    assert "tool_calls" not in message
    assert result["choices"][0]["finish_reason"] == "stop"
    assert result["aetherya"]["refused"] == 1


def test_the_model_is_told_why_a_call_was_refused() -> None:
    """
    A refusal delivered as a silently dropped call just gets retried. The
    reason goes into the transcript so the model can replan.
    """
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "rm -rf /"})]))
    result = _gateway(upstream, phase=2).complete({"messages": []})

    content = result["choices"][0]["message"]["content"]
    assert "ÆTHERYA" in content
    assert "Refused `shell`" in content


def test_existing_assistant_text_is_preserved_alongside_the_refusal() -> None:
    upstream = _FakeOpenAI(
        _completion([_call("shell", {"command": "rm -rf /"})], content="Cleaning up now.")
    )
    content = _gateway(upstream, phase=2).complete({"messages": []})["choices"][0]["message"][
        "content"
    ]
    assert content.startswith("Cleaning up now.")
    assert "Refused" in content


def test_allowed_calls_survive_when_a_sibling_is_refused() -> None:
    """A batch must not be refused wholesale because one member was."""
    upstream = _FakeOpenAI(
        _completion(
            [
                _call("shell", {"command": "ls -la"}, "ok"),
                _call("shell", {"command": "rm -rf /"}, "bad"),
            ]
        )
    )
    result = _gateway(upstream, phase=2).complete({"messages": []})

    kept = result["choices"][0]["message"]["tool_calls"]
    assert [c["id"] for c in kept] == ["ok"]
    assert result["choices"][0]["finish_reason"] == "tool_calls"


def test_a_clean_response_is_returned_untouched_apart_from_the_trace() -> None:
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "ls -la"})]))
    result = _gateway(upstream, phase=3, actor="robert").complete({"messages": []})

    assert result["choices"][0]["message"]["tool_calls"]
    assert result["aetherya"]["refused"] == 0


def test_an_actor_absent_from_the_capability_matrix_is_denied_everything() -> None:
    """
    The trap this gateway makes easy to fall into: point it at a policy whose
    capability matrix has never heard of your agent, and phase 3 denies every
    single call. Recorded here because the behaviour is correct and the
    failure mode is silent until phase 3.
    """
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "ls -la"})]))
    result = _gateway(upstream, phase=3, actor="nobody").complete({"messages": []})

    assert result["aetherya"]["refused"] == 1
    assert "unknown actor" in result["aetherya"]["gated"][0]["reason"]


def test_a_response_without_tool_calls_is_passed_straight_through() -> None:
    upstream = _FakeOpenAI(_completion(content="Just answering."))
    result = _gateway(upstream, phase=3).complete({"messages": []})

    assert "aetherya" not in result
    assert result["choices"][0]["message"]["content"] == "Just answering."


def test_a_response_with_no_choices_is_passed_through() -> None:
    result = _gateway(_FakeOpenAI({"id": "x", "choices": []})).complete({"messages": []})
    assert result["choices"] == []


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_every_gated_call_is_written_to_the_audit_trail(tmp_path: Path) -> None:
    audit_path = tmp_path / "decisions.jsonl"
    upstream = _FakeOpenAI(
        _completion(
            [
                _call("shell", {"command": "ls -la"}, "1"),
                _call("shell", {"command": "rm -rf /"}, "2"),
            ]
        )
    )
    _gateway(upstream, phase=2, audit=AuditLogger(str(audit_path))).complete({"messages": []})

    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert {row["actor"] for row in rows} == {"openclaw"}


# ---------------------------------------------------------------------------
# Upstream selection and failure
# ---------------------------------------------------------------------------


def test_a_response_whose_message_is_not_an_object_is_passed_through() -> None:
    result = _gateway(_FakeOpenAI({"choices": [{"index": 0, "message": "oops"}]})).complete(
        {"messages": []}
    )
    assert result["choices"][0]["message"] == "oops"


def test_a_response_whose_choice_is_not_an_object_is_passed_through() -> None:
    result = _gateway(_FakeOpenAI({"choices": ["oops"]})).complete({"messages": []})
    assert result["choices"] == ["oops"]


def test_the_real_client_is_constructed_once_and_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Constructing an SDK client per request would open a connection pool per
    request. The gateway is built once per process for the same reason.
    """
    built: list[int] = []

    class _SDK:
        class OpenAI:
            def __init__(self) -> None:
                built.append(1)
                self.chat = self
                self.completions = self

            def create(self, **kwargs: Any) -> Any:
                return _completion(content="hi")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr("importlib.import_module", lambda name: _SDK)

    gateway = AetheryaGateway(
        GatewaySettings(provider="openai", model="gpt-4o-mini", actor="robert"),
        constitution=_constitution(),
        cfg=load_policy_config(Path("config/policy.yaml")),
    )
    gateway.complete({"messages": []})
    gateway.complete({"messages": []})
    assert built == [1]


def test_a_missing_sdk_names_the_extra_that_installs_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    def _missing(name: str) -> Any:
        raise ImportError(name)

    monkeypatch.setattr("importlib.import_module", _missing)
    with pytest.raises(UpstreamError, match=r'pip install -e "\.\[anthropic\]"'):
        _gateway(None, provider="anthropic").complete({"messages": []})


def test_an_sdk_without_the_expected_client_class_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guards against a shadowing `openai.py` on the path pretending to be the SDK."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr("importlib.import_module", lambda name: object())
    with pytest.raises(UpstreamError, match="does not expose OpenAI"):
        _gateway(None).complete({"messages": []})


def test_an_unsupported_provider_is_rejected() -> None:
    gateway = _gateway(None, provider="cohere")
    with pytest.raises(UpstreamError, match="unsupported provider"):
        gateway.complete({"messages": []})


def test_a_missing_openai_key_is_reported_as_an_upstream_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(UpstreamError, match="OPENAI_API_KEY"):
        _gateway(None).complete({"messages": []})


def test_a_missing_anthropic_key_is_reported_as_an_upstream_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(UpstreamError, match="ANTHROPIC_API_KEY"):
        _gateway(None, provider="anthropic").complete({"messages": []})


def test_an_upstream_exception_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    The caller must be able to tell a boundary failure from a model failure;
    an agent that confuses them retries the wrong thing.
    """
    gateway = _gateway(_FakeOpenAI(RuntimeError("connection reset")))
    with pytest.raises(UpstreamError, match="RuntimeError: connection reset"):
        gateway.complete({"messages": []})


def test_the_stream_flag_is_not_forwarded_upstream() -> None:
    """We buffer to gate; asking the upstream to stream would defeat that."""
    upstream = _FakeOpenAI(_completion(content="hi"))
    _gateway(upstream).complete({"messages": [], "stream": True})
    assert "stream" not in upstream.requests[0]


def test_the_configured_model_is_used_when_the_body_omits_one() -> None:
    upstream = _FakeOpenAI(_completion(content="hi"))
    _gateway(upstream).complete({"messages": []})
    assert upstream.requests[0]["model"] == "gpt-4o-mini"


def test_the_body_model_wins_over_the_configured_default() -> None:
    upstream = _FakeOpenAI(_completion(content="hi"))
    _gateway(upstream).complete({"messages": [], "model": "gpt-4o"})
    assert upstream.requests[0]["model"] == "gpt-4o"


def test_a_pydantic_style_response_is_unwrapped() -> None:
    class _Model:
        def model_dump(self) -> dict[str, Any]:
            return _completion(content="hi")

    result = _gateway(_FakeOpenAI(_Model())).complete({"messages": []})
    assert result["choices"][0]["message"]["content"] == "hi"


# ---------------------------------------------------------------------------
# Streaming shape
# ---------------------------------------------------------------------------


def test_streaming_emits_a_well_formed_frame_sequence() -> None:
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "ls -la"})], content="reading"))
    frames = _gateway(upstream).stream({"messages": [], "stream": True})

    assert frames[0]["choices"][0]["delta"] == {"role": "assistant"}
    assert frames[1]["choices"][0]["delta"]["content"] == "reading"
    assert frames[2]["choices"][0]["delta"]["tool_calls"]
    assert frames[-1]["choices"][0]["finish_reason"] == "tool_calls"
    assert {f["object"] for f in frames} == {"chat.completion.chunk"}


def test_streaming_a_refusal_carries_the_reason() -> None:
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "rm -rf /"})]))
    frames = _gateway(upstream, phase=2).stream({"messages": [], "stream": True})

    text = "".join(str(f["choices"][0]["delta"].get("content", "")) for f in frames)
    assert "Refused `shell`" in text
    assert frames[-1]["choices"][0]["finish_reason"] == "stop"


def test_streaming_a_response_with_no_choices_still_terminates() -> None:
    frames = _gateway(_FakeOpenAI({"id": "x", "choices": []})).stream({"messages": []})
    assert frames[-1]["choices"][0]["finish_reason"] == "stop"


# ---------------------------------------------------------------------------
# Anthropic translation
# ---------------------------------------------------------------------------


class _Block:
    def __init__(self, **fields: Any) -> None:
        self.__dict__.update(fields)


class _AnthropicResponse:
    def __init__(self, content: list[Any], stop_reason: str = "end_turn") -> None:
        self.id = "msg_1"
        self.model = "claude-opus-5"
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _Block(input_tokens=10, output_tokens=5)


class _FakeAnthropic:
    def __init__(self, response: Any) -> None:
        self._response = response
        self.requests: list[dict[str, Any]] = []
        self.messages = self  # type: ignore[assignment]

    def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        return self._response


def test_anthropic_tool_use_becomes_an_openai_tool_call() -> None:
    upstream = _FakeAnthropic(
        _AnthropicResponse(
            [
                _Block(type="text", text="Deleting."),
                _Block(type="tool_use", id="toolu_1", name="shell", input={"command": "rm -rf /"}),
            ],
            stop_reason="tool_use",
        )
    )
    result = _gateway(upstream, phase=2, provider="anthropic").complete({"messages": []})

    assert result["aetherya"]["refused"] == 1
    assert result["usage"]["total_tokens"] == 15


def test_anthropic_text_only_responses_translate() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="Hello")]))
    result = _gateway(upstream, provider="anthropic").complete({"messages": []})

    assert result["choices"][0]["message"]["content"] == "Hello"
    assert result["choices"][0]["finish_reason"] == "stop"


def test_anthropic_requests_use_adaptive_thinking_and_no_sampling_params() -> None:
    """
    Claude Opus 5 rejects `budget_tokens`, `temperature`, `top_p` and `top_k`
    with a 400. Forwarding them from the chat-completions body would break
    every request.
    """
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {"messages": [{"role": "user", "content": "hi"}], "temperature": 0.7, "top_p": 0.9}
    )

    request = upstream.requests[0]
    assert request["thinking"] == {"type": "adaptive"}
    for rejected in ("temperature", "top_p", "top_k", "budget_tokens"):
        assert rejected not in request


def test_system_messages_are_hoisted_to_the_system_parameter() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {
            "messages": [
                {"role": "system", "content": "Be terse."},
                {"role": "system", "content": "Be safe."},
                {"role": "user", "content": "hi"},
            ]
        }
    )

    request = upstream.requests[0]
    assert request["system"] == "Be terse.\n\nBe safe."
    assert [m["role"] for m in request["messages"]] == ["user"]


def test_tool_results_are_translated_to_anthropic_blocks() -> None:
    """
    The agent's next turn carries the tool output. Without this translation the
    conversation would break on the second round trip.
    """
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {
            "messages": [
                {"role": "user", "content": "list files"},
                {
                    "role": "assistant",
                    "content": "calling",
                    "tool_calls": [_call("shell", {"command": "ls"}, "toolu_1")],
                },
                {"role": "tool", "tool_call_id": "toolu_1", "content": "a.txt"},
            ]
        }
    )

    messages = upstream.requests[0]["messages"]
    assistant = messages[1]["content"]
    assert assistant[0] == {"type": "text", "text": "calling"}
    assert assistant[1]["type"] == "tool_use"
    assert assistant[1]["input"] == {"command": "ls"}
    assert messages[2]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "toolu_1",
        "content": "a.txt",
    }


def test_tool_schemas_are_translated() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    schema = {"type": "object", "properties": {"command": {"type": "string"}}}
    _gateway(upstream, provider="anthropic").complete(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "shell",
                        "description": "Run a command",
                        "parameters": schema,
                    },
                }
            ],
        }
    )

    assert upstream.requests[0]["tools"] == [
        {"name": "shell", "description": "Run a command", "input_schema": schema}
    ]


def test_a_tool_without_a_schema_gets_an_empty_object_schema() -> None:
    """Anthropic requires `input_schema`; omitting it is a 400."""
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {"messages": [], "tools": [{"type": "function", "function": {"name": "noop"}}]}
    )

    assert upstream.requests[0]["tools"][0]["input_schema"] == {"type": "object", "properties": {}}


def test_no_tools_means_no_tools_key() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete({"messages": [], "tools": []})
    assert "tools" not in upstream.requests[0]


def test_malformed_messages_do_not_crash_the_translation() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete({"messages": ["not a dict", None]})
    assert upstream.requests[0]["messages"] == [{"role": "user", "content": ""}] * 2


def test_a_non_dict_body_is_tolerated() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    result = _gateway(upstream, provider="anthropic").complete([])  # type: ignore[arg-type]
    assert result["choices"][0]["message"]["content"] == "ok"


def test_the_effort_level_is_configurable() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    gateway = AetheryaGateway(
        GatewaySettings(provider="anthropic", model="claude-opus-5", anthropic_effort="medium"),
        constitution=_constitution(),
        cfg=load_policy_config(Path("config/policy.yaml")),
        upstream=upstream,
    )
    gateway.complete({"messages": []})
    assert upstream.requests[0]["output_config"] == {"effort": "medium"}


def test_the_action_contract_is_what_the_engine_receives() -> None:
    """Guard against the mapping drifting away from the engine's contract."""
    action = tool_call_to_action("shell", {"command": "ls"})
    assert isinstance(action, ActionRequest)
    assert action.mode_hint == "operative"


def test_an_empty_system_message_does_not_produce_an_empty_system_block() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {"messages": [{"role": "system", "content": ""}, {"role": "user", "content": "hi"}]}
    )
    assert "system" not in upstream.requests[0]


def test_an_assistant_tool_call_without_text_omits_the_text_block() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {
            "messages": [
                {"role": "assistant", "content": None, "tool_calls": [_call("shell", {"c": "ls"})]}
            ]
        }
    )
    blocks = upstream.requests[0]["messages"][0]["content"]
    assert [b["type"] for b in blocks] == ["tool_use"]


def test_unknown_anthropic_block_types_are_ignored() -> None:
    """
    Adaptive thinking emits `thinking` blocks. They are not part of the
    chat-completions shape and must not leak into the agent's transcript.
    """
    upstream = _FakeAnthropic(
        _AnthropicResponse(
            [
                _Block(type="thinking", thinking="deliberating"),
                _Block(type="text", text="answer"),
            ]
        )
    )
    result = _gateway(upstream, provider="anthropic").complete({"messages": []})
    assert result["choices"][0]["message"]["content"] == "answer"


def test_a_malformed_tool_call_entry_is_tolerated_in_translation() -> None:
    upstream = _FakeAnthropic(_AnthropicResponse([_Block(type="text", text="ok")]))
    _gateway(upstream, provider="anthropic").complete(
        {"messages": [{"role": "assistant", "content": "x", "tool_calls": ["not a dict"]}]}
    )
    blocks = upstream.requests[0]["messages"][0]["content"]
    assert blocks[1] == {"type": "tool_use", "id": "", "name": "", "input": {}}


def test_streamed_tool_calls_carry_their_index() -> None:
    """
    Clients reassemble streaming tool calls by index. Two calls emitted without
    one get merged into a single malformed call.
    """
    upstream = _FakeOpenAI(
        _completion([_call("shell", {"command": "ls"}, "a"), _call("http", {"url": "x"}, "b")])
    )
    frames = _gateway(upstream).stream({"messages": []})
    calls = next(f for f in frames if f["choices"][0]["delta"].get("tool_calls"))["choices"][0][
        "delta"
    ]["tool_calls"]
    assert [c["index"] for c in calls] == [0, 1]
    assert [c["id"] for c in calls] == ["a", "b"]


def test_an_escalation_is_refused_rather_than_held() -> None:
    """
    A single chat-completions call has no approval round trip, so phase 3
    cannot hold an action for a human — it refuses it. Documented in
    docs/gateway-openclaw.md; asserted here so the two cannot drift.
    """
    call = _call("filesystem", {"path": "/etc/hosts", "operation": "write"})
    result = _gateway(_FakeOpenAI(_completion([call])), phase=3, actor="robert").complete(
        {"messages": []}
    )

    trace = result["aetherya"]["gated"][0]
    assert trace["state"] == "escalate"
    assert trace["executed"] is False
    assert "Refused `filesystem`" in result["choices"][0]["message"]["content"]


def test_the_same_escalation_executes_in_phase_2() -> None:
    """The pair above and below is the whole reason phases exist."""
    call = _call("filesystem", {"path": "/etc/hosts", "operation": "write"})
    result = _gateway(_FakeOpenAI(_completion([call])), phase=2, actor="robert").complete(
        {"messages": []}
    )

    assert result["aetherya"]["gated"][0]["state"] == "escalate"
    assert result["choices"][0]["message"]["tool_calls"]
    assert result["aetherya"]["shadow_gap"] == 1


def test_the_trace_names_what_was_refused() -> None:
    """
    A refused call is stripped from the response, so the trace is the only
    surviving record of what the model proposed. Without the arguments it names
    a verdict but not the thing that earned it, which an operator cannot act on.
    """
    upstream = _FakeOpenAI(_completion([_call("shell", {"command": "rm -rf /"})]))
    result = _gateway(upstream, phase=2).complete({"messages": []})

    assert "tool_calls" not in result["choices"][0]["message"]
    gated = result["aetherya"]["gated"][0]
    assert gated["arguments"] == {"command": "rm -rf /"}
    assert gated["executed"] is False
