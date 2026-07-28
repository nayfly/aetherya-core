from __future__ import annotations

import importlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Final

from aetherya.actions import ActionRequest
from aetherya.audit import AuditLogger
from aetherya.config import PolicyConfig
from aetherya.constitution import Constitution
from aetherya.enforcement import EnforcementPhase, apply_enforcement, resolve_phase
from aetherya.pipeline import run_pipeline_structured

# ---------------------------------------------------------------------------
# OpenAI-compatible gateway.
#
# The sidecar client requires modifying the agent. This does not: it speaks the
# OpenAI chat-completions protocol, so any runtime that can point at a custom
# OpenAI-compatible provider — OpenClaw, LiteLLM, most frameworks — routes
# through it by configuration alone.
#
#     OpenClaw ──► ÆTHERYA gateway ──► OpenAI | Anthropic
#                        │
#                   every tool call the model proposes is ruled on
#                   before the agent ever sees it
#
# GATING REQUIRES BUFFERING. A decision cannot be made about half a tool call,
# so the upstream response is completed before anything reaches the client. With
# `stream: true` the gateway still answers in SSE frames, but they are emitted
# after the verdict — the protocol is preserved, the token-by-token latency is
# not. That is the honest cost of putting a boundary here.
# ---------------------------------------------------------------------------


class UpstreamError(RuntimeError):
    """The upstream provider could not be reached or returned an unusable answer."""


# provider -> (api key env var, module, client class, pyproject extra)
_PROVIDERS: Final[dict[str, tuple[str, str, str, str]]] = {
    "openai": ("OPENAI_API_KEY", "openai", "OpenAI", "llm"),
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic", "Anthropic", "anthropic"),
}


@dataclass
class GatewaySettings:
    provider: str = "openai"  # openai | anthropic
    model: str = "gpt-4o-mini"
    actor: str = "openclaw"
    phase: int = 1
    max_tokens: int = 4096
    # Anthropic-only: adaptive thinking is the current contract; `budget_tokens`
    # and sampling parameters are rejected by Claude Opus 5.
    anthropic_effort: str = "high"


@dataclass
class GatedCall:
    """One tool call the model proposed, and what the policy said about it."""

    call_id: str
    name: str
    arguments: dict[str, Any]
    state: str
    risk_score: int
    reason: str
    execute: bool
    shadow_gap: bool


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def tool_call_to_action(name: str, arguments: dict[str, Any]) -> ActionRequest:
    """
    Translate a proposed tool call into the engine's contract.

    The gateway does not know the agent's tool vocabulary, so the mapping is
    deliberately generic: the tool name becomes the declared tool and the
    arguments become the parameters. `raw_input` carries a readable rendering
    because ProceduralGuard and JailbreakGuard read it regardless of the
    declared intent — a destructive command hidden in an argument is still seen.
    """
    rendered = " ".join(str(v) for v in arguments.values() if v is not None)
    return ActionRequest(
        raw_input=f"{name} {rendered}".strip(),
        intent="operate",
        mode_hint="operative",
        tool=name,
        target=str(arguments.get("path") or arguments.get("target") or "") or None,
        parameters={str(k): v for k, v in arguments.items()},
    )


class AetheryaGateway:
    """
    Policy boundary in the shape of an OpenAI-compatible provider.

    Construct once per process: it holds the constitution and the upstream
    client, both of which are expensive to rebuild per request.
    """

    def __init__(
        self,
        settings: GatewaySettings,
        *,
        constitution: Constitution,
        cfg: PolicyConfig,
        audit: AuditLogger | None = None,
        upstream: Any = None,
    ) -> None:
        self.settings = settings
        self.constitution = constitution
        self.cfg = cfg
        self.audit = audit
        self.phase: EnforcementPhase = resolve_phase(settings.phase)
        self._upstream = upstream

    # -- upstream -------------------------------------------------------------

    def _client(self) -> Any:
        if self._upstream is not None:
            return self._upstream

        provider = self.settings.provider.strip().lower()
        if provider not in _PROVIDERS:
            raise UpstreamError(f"unsupported provider: {self.settings.provider}")
        key_env, module_name, class_name, extra = _PROVIDERS[provider]

        # The key is checked before the import so a missing key reports itself
        # as a missing key, not as a missing package.
        if not os.getenv(key_env, "").strip():
            raise UpstreamError(f"{key_env} is not set")

        # Imported by name, like llm_provider does: the SDKs are optional
        # extras and a module-level import would make them mandatory for
        # type-checking and for every deployment that uses the other provider.
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise UpstreamError(
                f'{module_name} is not installed — pip install -e ".[{extra}]"'
            ) from exc
        client_cls = getattr(module, class_name, None)
        if not callable(client_cls):
            raise UpstreamError(f"{module_name} does not expose {class_name}")

        self._upstream = client_cls()
        return self._upstream

    def _call_openai(self, body: dict[str, Any]) -> dict[str, Any]:
        request = {k: v for k, v in body.items() if k != "stream"}
        request.setdefault("model", self.settings.model)
        response = self._client().chat.completions.create(**request)
        return response.model_dump() if hasattr(response, "model_dump") else dict(response)

    def _call_anthropic(self, body: dict[str, Any]) -> dict[str, Any]:
        """
        Bridge chat-completions → Messages API → chat-completions.

        Claude Opus 5 rejects `temperature`/`top_p`/`top_k` and `budget_tokens`,
        so those are dropped rather than forwarded; depth is set with adaptive
        thinking plus an effort level.
        """
        system_parts: list[str] = []
        messages: list[dict[str, Any]] = []
        for raw in body.get("messages", []):
            message = _as_dict(raw)
            role = str(message.get("role", "user"))
            content = message.get("content")
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "tool":
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": str(message.get("tool_call_id", "")),
                                "content": str(content or ""),
                            }
                        ],
                    }
                )
                continue
            if role == "assistant" and message.get("tool_calls"):
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for raw_call in message["tool_calls"]:
                    call = _as_dict(raw_call)
                    fn = _as_dict(call.get("function"))
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": str(call.get("id", "")),
                            "name": str(fn.get("name", "")),
                            "input": _parse_arguments(fn.get("arguments")),
                        }
                    )
                messages.append({"role": "assistant", "content": blocks})
                continue
            messages.append({"role": role, "content": str(content or "")})

        request: dict[str, Any] = {
            "model": body.get("model") or self.settings.model,
            "max_tokens": int(body.get("max_tokens") or self.settings.max_tokens),
            "messages": messages,
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": self.settings.anthropic_effort},
        }
        if system_parts:
            request["system"] = "\n\n".join(system_parts)

        tools = [
            {
                "name": str(_as_dict(_as_dict(t).get("function")).get("name", "")),
                "description": str(_as_dict(_as_dict(t).get("function")).get("description", "")),
                "input_schema": _as_dict(_as_dict(t).get("function")).get("parameters")
                or {"type": "object", "properties": {}},
            }
            for t in body.get("tools", [])
        ]
        if tools:
            request["tools"] = tools

        response = self._client().messages.create(**request)
        return _anthropic_to_chat_completion(response, request["model"])

    def _upstream_completion(self, body: dict[str, Any]) -> dict[str, Any]:
        provider = self.settings.provider.strip().lower()
        try:
            if provider == "anthropic":
                return self._call_anthropic(body)
            return self._call_openai(body)
        except UpstreamError:
            raise
        except Exception as exc:
            raise UpstreamError(f"{type(exc).__name__}: {exc}") from exc

    # -- gating ---------------------------------------------------------------

    def gate_tool_calls(self, calls: list[dict[str, Any]]) -> list[GatedCall]:
        """Rule on every proposed tool call, in order."""
        gated: list[GatedCall] = []
        for raw in calls:
            call = _as_dict(raw)
            fn = _as_dict(call.get("function"))
            name = str(fn.get("name", ""))
            arguments = _parse_arguments(fn.get("arguments"))

            decision = run_pipeline_structured(
                tool_call_to_action(name, arguments),
                constitution=self.constitution,
                actor=self.settings.actor,
                cfg=self.cfg,
                audit=self.audit,
            )
            enforcement = apply_enforcement(decision, self.phase)
            gated.append(
                GatedCall(
                    call_id=str(call.get("id", "")),
                    name=name,
                    arguments=arguments,
                    state=decision.state,
                    risk_score=decision.risk_score,
                    reason=decision.reason,
                    execute=enforcement.execute,
                    shadow_gap=enforcement.shadow_gap,
                )
            )
        return gated

    def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        """Handle one /v1/chat/completions request."""
        payload = _as_dict(body)
        completion = self._upstream_completion(payload)

        choices = completion.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return completion

        # Held by reference on purpose: refusals are applied by editing the
        # response the agent receives, so a copy here would silently discard
        # every enforcement decision below.
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            return completion
        calls = list(message.get("tool_calls") or [])
        if not calls:
            return completion

        gated = self.gate_tool_calls(calls)
        refused = [c for c in gated if not c.execute]

        if not refused:
            completion["aetherya"] = _trace(gated, self.phase)
            return completion

        # Refused calls are removed and explained in the assistant's text. The
        # model sees why, in its own transcript, and can replan — a refusal that
        # arrives as a dropped call with no explanation just gets retried.
        kept = [raw for raw, c in zip(calls, gated, strict=True) if c.execute]
        notice = "\n".join(f"[ÆTHERYA] Refused `{c.name}`: {c.reason}" for c in refused)
        existing = str(message.get("content") or "")
        message["content"] = f"{existing}\n{notice}".strip() if existing else notice
        if kept:
            message["tool_calls"] = kept
        else:
            message.pop("tool_calls", None)
            choice["finish_reason"] = "stop"

        completion["aetherya"] = _trace(gated, self.phase)
        return completion

    def stream(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """
        SSE frames for a `stream: true` request.

        The verdict needs the whole tool call, so the response is completed
        first and then emitted as frames. Clients that expect the streaming
        protocol keep working; token-by-token latency does not survive.
        """
        completion = self.complete(body)
        choices = completion.get("choices") or []
        message = _as_dict(_as_dict(choices[0]).get("message")) if choices else {}

        base = {
            "id": completion.get("id", f"chatcmpl-{uuid.uuid4().hex}"),
            "object": "chat.completion.chunk",
            "created": completion.get("created", int(time.time())),
            "model": completion.get("model", self.settings.model),
        }
        frames: list[dict[str, Any]] = [
            {
                **base,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
        ]
        if message.get("content"):
            frames.append(
                {
                    **base,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": message["content"]},
                            "finish_reason": None,
                        }
                    ],
                }
            )
        if message.get("tool_calls"):
            # `index` is how a streaming client places each call while
            # reassembling deltas. We emit them whole, but a client that
            # accumulates by index would merge two calls into one without it.
            indexed = [
                {**_as_dict(call), "index": position}
                for position, call in enumerate(message["tool_calls"])
            ]
            frames.append(
                {
                    **base,
                    "choices": [
                        {"index": 0, "delta": {"tool_calls": indexed}, "finish_reason": None}
                    ],
                }
            )
        finish = _as_dict(choices[0]).get("finish_reason") if choices else "stop"
        frames.append(
            {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish or "stop"}]}
        )
        return frames


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Malformed arguments still get gated — on the raw text, which is what
        # a guard needs to see. Dropping them here would skip the check.
        return {"_raw": raw}
    return parsed if isinstance(parsed, dict) else {"_value": parsed}


def _trace(gated: list[GatedCall], phase: EnforcementPhase) -> dict[str, Any]:
    return {
        "phase": phase.number,
        "phase_name": phase.name,
        "gated": [
            {
                "id": c.call_id,
                "tool": c.name,
                "state": c.state,
                "risk_score": c.risk_score,
                "executed": c.execute,
                "shadow_gap": c.shadow_gap,
                "reason": c.reason,
            }
            for c in gated
        ],
        "refused": sum(1 for c in gated if not c.execute),
        "shadow_gap": sum(1 for c in gated if c.shadow_gap),
    }


def _anthropic_to_chat_completion(response: Any, model: str) -> dict[str, Any]:
    """Render an Anthropic Messages response in chat-completions shape."""
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in getattr(response, "content", []) or []:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text_parts.append(str(getattr(block, "text", "")))
        elif block_type == "tool_use":
            tool_calls.append(
                {
                    "id": str(getattr(block, "id", "")),
                    "type": "function",
                    "function": {
                        "name": str(getattr(block, "name", "")),
                        "arguments": json.dumps(getattr(block, "input", {}) or {}),
                    },
                }
            )

    message: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls

    stop_reason = getattr(response, "stop_reason", None)
    usage = getattr(response, "usage", None)
    return {
        "id": str(getattr(response, "id", f"chatcmpl-{uuid.uuid4().hex}")),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": str(getattr(response, "model", model)),
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }
        ],
        "usage": {
            "prompt_tokens": int(getattr(usage, "input_tokens", 0) or 0),
            "completion_tokens": int(getattr(usage, "output_tokens", 0) or 0),
            "total_tokens": int(getattr(usage, "input_tokens", 0) or 0)
            + int(getattr(usage, "output_tokens", 0) or 0),
        },
        "aetherya_upstream_stop_reason": stop_reason,
    }
