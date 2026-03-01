from __future__ import annotations

import sys
import types
from dataclasses import dataclass

import pytest

import aetherya.llm_provider as llm_provider
from aetherya.llm_provider import (
    DryRunLLMProvider,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    OpenAILLMProvider,
    ensure_llm_provider,
)


@dataclass
class DummyMeta:
    value: str


def test_llm_request_validate_rejects_empty_messages() -> None:
    request = LLMRequest(model="gpt-dry", messages=[])
    with pytest.raises(ValueError, match="messages must be a non-empty list"):
        request.validate()


def test_llm_message_validate_rejects_invalid_role() -> None:
    message = LLMMessage(role="tool", content="hello")
    with pytest.raises(ValueError, match="message role"):
        message.validate()


def test_llm_message_validate_rejects_empty_content() -> None:
    message = LLMMessage(role="user", content="   ")
    with pytest.raises(ValueError, match="message content"):
        message.validate()


def test_llm_request_validate_rejects_empty_model() -> None:
    request = LLMRequest(model=" ", messages=[LLMMessage(role="user", content="ok")])
    with pytest.raises(ValueError, match="model must be non-empty str"):
        request.validate()


def test_llm_request_validate_rejects_non_llm_message_item() -> None:
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="ok"), "bad"],  # type: ignore[list-item]
    )
    with pytest.raises(ValueError, match="messages must contain LLMMessage"):
        request.validate()


def test_llm_request_validate_rejects_nan_temperature() -> None:
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="ok")],
        temperature=float("nan"),
    )
    with pytest.raises(ValueError, match="temperature must be numeric"):
        request.validate()


def test_llm_request_validate_rejects_out_of_range_temperature() -> None:
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="ok")],
        temperature=3.0,
    )
    with pytest.raises(ValueError, match="temperature must be between 0.0 and 2.0"):
        request.validate()


def test_llm_request_validate_rejects_non_positive_max_tokens() -> None:
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="ok")],
        max_tokens=0,
    )
    with pytest.raises(ValueError, match="max_tokens must be positive int"):
        request.validate()


def test_llm_request_validate_rejects_non_dict_metadata() -> None:
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="ok")],
        metadata=["bad"],  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="metadata must be dict"):
        request.validate()


def test_dry_run_provider_returns_deterministic_response() -> None:
    provider = DryRunLLMProvider(seed="test-seed")
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="analyze this command please")],
        temperature=0.2,
        max_tokens=32,
        metadata={
            "mode": "consultive",
            "steps": ("one", "two"),
            "ids": {"b", "a"},
            "finite": 1.5,
            "ratio": float("inf"),
            "obj": DummyMeta("x"),
        },
    )

    response1 = provider.generate(request)
    response2 = provider.generate(request)

    assert response1.response_id == response2.response_id
    assert response1.output_text == response2.output_text
    assert response1.metadata["request_hash"] == response2.metadata["request_hash"]
    assert response1.dry_run is True


def test_dry_run_provider_scans_messages_until_user_found() -> None:
    provider = DryRunLLMProvider(seed="test-seed")
    request = LLMRequest(
        model="gpt-dry",
        messages=[
            LLMMessage(role="user", content="final user intent"),
            LLMMessage(role="assistant", content="previous assistant answer"),
        ],
        max_tokens=32,
    )
    response = provider.generate(request)
    assert "final user intent" in response.output_text


def test_dry_run_provider_truncates_long_preview() -> None:
    provider = DryRunLLMProvider(seed="test-seed")
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="x" * 120)],
        max_tokens=64,
    )
    response = provider.generate(request)
    assert "..." in response.output_text


def test_dry_run_provider_uses_fallback_when_no_user_message() -> None:
    provider = DryRunLLMProvider(seed="test-seed")
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="system", content="you are deterministic")],
        max_tokens=32,
    )
    response = provider.generate(request)
    assert "no-user-message" in response.output_text


def test_dry_run_provider_changes_response_when_request_changes() -> None:
    provider = DryRunLLMProvider(seed="test-seed")
    request_a = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="first prompt")],
        max_tokens=32,
    )
    request_b = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="second prompt")],
        max_tokens=32,
    )

    response_a = provider.generate(request_a)
    response_b = provider.generate(request_b)

    assert response_a.response_id != response_b.response_id
    assert response_a.metadata["request_hash"] != response_b.metadata["request_hash"]


def test_dry_run_provider_suggested_state_can_be_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm_provider, "_request_hash", lambda seed, request: "ffff" + ("0" * 60))
    provider = DryRunLLMProvider(seed="test-seed")
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="high-risk analysis")],
        max_tokens=32,
    )
    response = provider.generate(request)
    assert response.metadata["suggested_state"] == "deny"


def test_dry_run_provider_suggested_state_can_be_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm_provider, "_request_hash", lambda seed, request: "0000" + ("1" * 60))
    provider = DryRunLLMProvider(seed="test-seed")
    request = LLMRequest(
        model="gpt-dry",
        messages=[LLMMessage(role="user", content="low-risk analysis")],
        max_tokens=32,
    )
    response = provider.generate(request)
    assert response.metadata["suggested_state"] == "allow"


def test_ensure_llm_provider_accepts_valid_provider() -> None:
    provider = DryRunLLMProvider()
    assert ensure_llm_provider(provider) is provider


def test_ensure_llm_provider_rejects_invalid_provider() -> None:
    with pytest.raises(ValueError, match="provider must implement LLMProvider"):
        ensure_llm_provider(object())


def test_llm_usage_validate_rejects_negative_prompt_tokens() -> None:
    usage = LLMUsage(prompt_tokens=-1, completion_tokens=0, total_tokens=0)
    with pytest.raises(ValueError, match="prompt_tokens"):
        usage.validate()


def test_llm_usage_validate_rejects_negative_completion_tokens() -> None:
    usage = LLMUsage(prompt_tokens=0, completion_tokens=-1, total_tokens=0)
    with pytest.raises(ValueError, match="completion_tokens"):
        usage.validate()


def test_llm_usage_validate_rejects_negative_total_tokens() -> None:
    usage = LLMUsage(prompt_tokens=0, completion_tokens=0, total_tokens=-1)
    with pytest.raises(ValueError, match="total_tokens must be >= 0"):
        usage.validate()


def test_llm_response_validate_rejects_bad_usage_contract() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider="dry_run",
        output_text="x",
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=999),
        dry_run=True,
    )
    with pytest.raises(ValueError, match="total_tokens must equal"):
        response.validate()


def test_llm_response_validate_rejects_empty_response_id() -> None:
    response = LLMResponse(
        response_id="",
        model="gpt-dry",
        provider="dry_run",
        output_text="x",
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=True,
    )
    with pytest.raises(ValueError, match="response_id must be non-empty str"):
        response.validate()


def test_llm_response_validate_rejects_empty_model() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model=" ",
        provider="dry_run",
        output_text="x",
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=True,
    )
    with pytest.raises(ValueError, match="model must be non-empty str"):
        response.validate()


def test_llm_response_validate_rejects_empty_provider() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider=" ",
        output_text="x",
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=True,
    )
    with pytest.raises(ValueError, match="provider must be non-empty str"):
        response.validate()


def test_llm_response_validate_rejects_non_str_output_text() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider="dry_run",
        output_text=1,  # type: ignore[arg-type]
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=True,
    )
    with pytest.raises(ValueError, match="output_text must be str"):
        response.validate()


def test_llm_response_validate_rejects_invalid_finish_reason() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider="dry_run",
        output_text="x",
        finish_reason="tool_call",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=True,
    )
    with pytest.raises(ValueError, match="finish_reason"):
        response.validate()


def test_llm_response_validate_rejects_invalid_usage_type() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider="dry_run",
        output_text="x",
        finish_reason="dry_run",
        usage="bad",  # type: ignore[arg-type]
        dry_run=True,
    )
    with pytest.raises(ValueError, match="usage must be LLMUsage"):
        response.validate()


def test_llm_response_validate_rejects_non_bool_dry_run() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider="dry_run",
        output_text="x",
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=1,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="dry_run must be bool"):
        response.validate()


def test_llm_response_validate_rejects_non_dict_metadata() -> None:
    response = LLMResponse(
        response_id="dryrun:abc",
        model="gpt-dry",
        provider="dry_run",
        output_text="x",
        finish_reason="dry_run",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        dry_run=True,
        metadata=["bad"],  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="metadata must be dict"):
        response.validate()


def test_openai_provider_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        OpenAILLMProvider()


def test_openai_provider_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError, match="timeout_sec must be > 0"):
        OpenAILLMProvider(api_key="sk-test", timeout_sec=0.0)


def test_openai_provider_import_error_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(name: str):  # noqa: ANN202
        raise ImportError(name)

    monkeypatch.setattr(llm_provider.importlib, "import_module", _boom)
    with pytest.raises(RuntimeError, match="openai package is not installed"):
        OpenAILLMProvider(api_key="sk-test")


def test_openai_provider_raises_when_sdk_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_module = types.ModuleType("openai")
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    with pytest.raises(RuntimeError, match="openai package is not installed"):
        OpenAILLMProvider(api_key="sk-test")


def test_openai_provider_generate_maps_chat_completion_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeUsage:
        prompt_tokens = 7
        completion_tokens = 5
        total_tokens = 12

    class FakeMessage:
        content = "shadow verdict text"

    class FakeChoice:
        message = FakeMessage()
        finish_reason = "length"

    class FakeCompletion:
        id = "chatcmpl-test"
        model = "gpt-4o-mini"
        usage = FakeUsage()
        choices = [FakeChoice()]

    class FakeCompletions:
        def __init__(self) -> None:
            self.last_kwargs: dict[str, object] = {}

        def create(self, **kwargs):  # noqa: ANN003,ANN202
            self.last_kwargs = dict(kwargs)
            return FakeCompletion()

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, **kwargs):  # noqa: ANN003
            self.kwargs = dict(kwargs)
            self.chat = FakeChat()

    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    provider = OpenAILLMProvider(api_key="sk-test", timeout_sec=3.5)
    request = LLMRequest(
        model="gpt-4o-mini",
        messages=[
            LLMMessage(role="system", content="shadow mode"),
            LLMMessage(role="user", content="analyze safely"),
        ],
        temperature=0.1,
        max_tokens=24,
    )

    response = provider.generate(request)
    assert response.provider == "openai"
    assert response.dry_run is False
    assert response.finish_reason == "length"
    assert response.usage.total_tokens == 12
    assert response.metadata["request_hash"]
    assert response.metadata["suggested_state"] in {
        "allow",
        "log_only",
        "require_confirm",
        "deny",
    }

    client = provider._client  # noqa: SLF001
    assert client.kwargs["timeout"] == 3.5
    assert client.chat.completions.last_kwargs["model"] == "gpt-4o-mini"


def test_openai_provider_includes_base_url_and_usage_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeUsage:
        prompt_tokens = "bad"
        completion_tokens = None
        total_tokens = "still-bad"

    class FakeMessage:
        content = 42

    class FakeChoice:
        message = FakeMessage()
        finish_reason = "unknown_reason"

    class FakeCompletion:
        id = ""
        model = ""
        usage = FakeUsage()
        choices = [FakeChoice()]

    class FakeCompletions:
        def create(self, **kwargs):  # noqa: ANN003,ANN202
            return FakeCompletion()

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, **kwargs):  # noqa: ANN003
            self.kwargs = dict(kwargs)
            self.chat = FakeChat()

    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    provider = OpenAILLMProvider(api_key="sk-test", base_url="https://proxy.local/v1")
    response = provider.generate(
        LLMRequest(
            model="gpt-4o-mini",
            messages=[LLMMessage(role="user", content="hello")],
            max_tokens=16,
        )
    )

    assert response.finish_reason == "stop"
    assert response.usage.prompt_tokens == 0
    assert response.usage.completion_tokens == 0
    assert response.usage.total_tokens == 0
    assert response.response_id.startswith("openai:")
    assert response.model == "gpt-4o-mini"
    assert response.output_text == "42"

    client = provider._client  # noqa: SLF001
    assert client.kwargs["base_url"] == "https://proxy.local/v1"


def test_openai_provider_rejects_completion_with_empty_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeCompletion:
        choices: list[object] = []

    class FakeCompletions:
        def create(self, **kwargs):  # noqa: ANN003,ANN202
            return FakeCompletion()

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, **kwargs):  # noqa: ANN003,ARG002
            self.chat = FakeChat()

    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    provider = OpenAILLMProvider(api_key="sk-test")
    with pytest.raises(RuntimeError, match="openai returned no choices"):
        provider.generate(
            LLMRequest(
                model="gpt-4o-mini",
                messages=[LLMMessage(role="user", content="hello")],
                max_tokens=16,
            )
        )


def test_openai_finish_reason_and_coerce_helpers_cover_stop_branch() -> None:
    assert llm_provider._map_openai_finish_reason("unexpected") == "stop"  # noqa: SLF001
    assert llm_provider._coerce_int("bad", 5) == 5  # noqa: SLF001
