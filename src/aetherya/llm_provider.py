from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

_VALID_MESSAGE_ROLES = frozenset({"system", "user", "assistant"})


class LLMFinishReason(StrEnum):
    DRY_RUN = "dry_run"
    STOP = "stop"
    LENGTH = "length"


@dataclass(frozen=True)
class LLMMessage:
    role: str
    content: str

    def validate(self) -> None:
        role = self.role.strip().lower()
        if role not in _VALID_MESSAGE_ROLES:
            raise ValueError("message role must be one of: system, user, assistant")
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("message content must be non-empty str")

    def normalized(self) -> dict[str, str]:
        self.validate()
        return {
            "role": self.role.strip().lower(),
            "content": self.content.strip(),
        }


@dataclass(frozen=True)
class LLMRequest:
    model: str
    messages: list[LLMMessage]
    temperature: float = 0.0
    max_tokens: int = 256
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("model must be non-empty str")
        if not isinstance(self.messages, list) or not self.messages:
            raise ValueError("messages must be a non-empty list")
        for message in self.messages:
            if not isinstance(message, LLMMessage):
                raise ValueError("messages must contain LLMMessage items")
            message.validate()
        if not isinstance(self.temperature, int | float) or math.isnan(float(self.temperature)):
            raise ValueError("temperature must be numeric")
        if not 0.0 <= float(self.temperature) <= 2.0:
            raise ValueError("temperature must be between 0.0 and 2.0")
        if not isinstance(self.max_tokens, int) or self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive int")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be dict")


@dataclass(frozen=True)
class LLMUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

    def validate(self) -> None:
        if not isinstance(self.prompt_tokens, int) or self.prompt_tokens < 0:
            raise ValueError("prompt_tokens must be >= 0")
        if not isinstance(self.completion_tokens, int) or self.completion_tokens < 0:
            raise ValueError("completion_tokens must be >= 0")
        if not isinstance(self.total_tokens, int) or self.total_tokens < 0:
            raise ValueError("total_tokens must be >= 0")
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("total_tokens must equal prompt_tokens + completion_tokens")


@dataclass(frozen=True)
class LLMResponse:
    response_id: str
    model: str
    provider: str
    output_text: str
    finish_reason: str
    usage: LLMUsage
    dry_run: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.response_id, str) or not self.response_id.strip():
            raise ValueError("response_id must be non-empty str")
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("model must be non-empty str")
        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("provider must be non-empty str")
        if not isinstance(self.output_text, str):
            raise ValueError("output_text must be str")
        if self.finish_reason not in set(reason.value for reason in LLMFinishReason):
            raise ValueError("finish_reason must be a valid LLMFinishReason")
        if not isinstance(self.usage, LLMUsage):
            raise ValueError("usage must be LLMUsage")
        self.usage.validate()
        if not isinstance(self.dry_run, bool):
            raise ValueError("dry_run must be bool")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be dict")


@runtime_checkable
class LLMProvider(Protocol):
    provider_name: str

    def generate(self, request: LLMRequest) -> LLMResponse: ...


def ensure_llm_provider(provider: Any) -> LLMProvider:
    if not isinstance(provider, LLMProvider):
        raise ValueError("provider must implement LLMProvider")
    return provider


def _normalize_payload(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return str(value)
    if isinstance(value, dict):
        return {str(k): _normalize_payload(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalize_payload(v) for v in value]
    if isinstance(value, set):
        normalized = [_normalize_payload(v) for v in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
    return f"<{type(value).__module__}.{type(value).__qualname__}>"


def _request_hash(seed: str, request: LLMRequest) -> str:
    payload = {
        "seed": seed,
        "model": request.model.strip(),
        "messages": [m.normalized() for m in request.messages],
        "temperature": float(request.temperature),
        "max_tokens": int(request.max_tokens),
        "metadata": _normalize_payload(request.metadata),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DryRunLLMProvider:
    provider_name = "dry_run"

    def __init__(self, seed: str = "aetherya:dry-run:v1") -> None:
        self.seed = seed

    def generate(self, request: LLMRequest) -> LLMResponse:
        request.validate()

        req_hash = _request_hash(self.seed, request)
        last_user_content = ""
        for message in reversed(request.messages):
            if message.role.strip().lower() == "user":
                last_user_content = message.content.strip()
                break

        preview = last_user_content.replace("\n", " ").strip()
        if len(preview) > 64:
            preview = f"{preview[:64]}..."
        if not preview:
            preview = "no-user-message"

        output_text = (
            f"[dry-run] provider={self.provider_name} model={request.model.strip()} "
            f"preview={preview} trace={req_hash[:12]}"
        )
        prompt_tokens = sum(
            max(1, len(message.content.strip().split())) for message in request.messages
        )
        completion_tokens = min(request.max_tokens, max(8, len(output_text.split())))

        usage = LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )
        response = LLMResponse(
            response_id=f"dryrun:{req_hash[:24]}",
            model=request.model.strip(),
            provider=self.provider_name,
            output_text=output_text,
            finish_reason=LLMFinishReason.DRY_RUN.value,
            usage=usage,
            dry_run=True,
            metadata={"request_hash": req_hash, "seed": self.seed},
        )
        response.validate()
        return response
