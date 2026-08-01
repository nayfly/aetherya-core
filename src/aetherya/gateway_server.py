from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from aetherya.audit import AuditLogger
from aetherya.config import load_policy_config
from aetherya.gateway import _PROVIDERS, AetheryaGateway, GatewaySettings, UpstreamError

DEFAULT_PORT = 8090
MAX_BODY_BYTES = 4_194_304


class GatewayHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    The subset of the OpenAI API an agent runtime actually needs to treat this
    as a provider: list the models, and complete a chat.
    """

    gateway: AetheryaGateway | None = None

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[gateway] {self.address_string()} {format % args}\n")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_payload(self, status: int, message: str, code: str) -> None:
        # OpenAI's error envelope, because the client parses it as one.
        self._send_json(status, {"error": {"message": message, "type": code, "code": code}})

    def _send_sse(self, frames: list[dict[str, Any]]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for frame in frames:
            self.wfile.write(f"data: {json.dumps(frame, ensure_ascii=False)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/health":
            gateway = self.gateway
            # A gateway with no upstream credential answers every completion
            # with a 502. Reporting that as healthy is a lie a readiness probe
            # would believe, so the key is part of the contract rather than
            # something you discover on the first real request.
            key_present = False
            if gateway is not None:
                key_env = _PROVIDERS.get(gateway.settings.provider.strip().lower())
                key_present = bool(key_env and os.getenv(key_env[0], "").strip())
            self._send_json(
                200,
                {
                    "ok": gateway is not None and key_present,
                    "provider": gateway.settings.provider if gateway else None,
                    "model": gateway.settings.model if gateway else None,
                    "phase": gateway.phase.number if gateway else None,
                    "phase_name": gateway.phase.name if gateway else None,
                    "upstream_key_present": key_present,
                },
            )
            return
        if path in {"/v1/models", "/models"}:
            gateway = self.gateway
            model = gateway.settings.model if gateway else "unknown"
            self._send_json(
                200,
                {
                    "object": "list",
                    "data": [{"id": model, "object": "model", "owned_by": "aetherya"}],
                },
            )
            return
        self._send_error_payload(404, f"unknown path: {path}", "not_found")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path not in {"/v1/chat/completions", "/chat/completions"}:
            self._send_error_payload(404, f"unknown path: {path}", "not_found")
            return

        gateway = self.gateway
        if gateway is None:
            self._send_error_payload(500, "gateway is not configured", "server_error")
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self._send_error_payload(400, "invalid Content-Length", "invalid_request_error")
            return
        if length > MAX_BODY_BYTES:
            self._send_error_payload(413, "request body too large", "invalid_request_error")
            return

        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            self._send_error_payload(400, f"invalid JSON body: {exc}", "invalid_request_error")
            return
        if not isinstance(body, dict):
            self._send_error_payload(400, "body must be a JSON object", "invalid_request_error")
            return

        try:
            if body.get("stream"):
                self._send_sse(gateway.stream(body))
            else:
                self._send_json(200, gateway.complete(body))
        except UpstreamError as exc:
            # The boundary failed, not the model. Say so distinctly — an agent
            # that cannot tell these apart will retry the wrong one.
            self._send_error_payload(502, f"upstream: {exc}", "upstream_error")
        except Exception as exc:  # noqa: BLE001
            self._send_error_payload(500, f"{type(exc).__name__}: {exc}", "server_error")


def build_gateway_server(host: str, port: int, *, gateway: AetheryaGateway) -> ThreadingHTTPServer:
    handler = type("_BoundGatewayHandler", (GatewayHTTPRequestHandler,), {"gateway": gateway})
    return ThreadingHTTPServer((host, port), handler)


def build_gateway(
    *,
    policy_path: Path,
    constitution_path: Path | None,
    audit_path: Path | None,
    settings: GatewaySettings,
) -> AetheryaGateway:
    from aetherya.cli import _default_constitution, _load_constitution

    cfg = load_policy_config(policy_path)
    constitution_kwargs = {
        "use_semantic": cfg.constitution_config.use_semantic,
        "semantic_violation_threshold": cfg.constitution_config.semantic_violation_threshold,
        "semantic_gray_zone_threshold": cfg.constitution_config.semantic_gray_zone_threshold,
        "semantic_max_risk": cfg.constitution_config.semantic_max_risk,
        "require_warm_semantic_model": cfg.constitution_config.require_warm_semantic_model,
    }
    constitution = (
        _load_constitution(constitution_path, **constitution_kwargs)  # type: ignore[arg-type]
        if constitution_path is not None
        else _default_constitution(**constitution_kwargs)  # type: ignore[arg-type]
    )

    check_actor_is_known(cfg.capability_matrix, settings.actor, settings.phase)

    audit = (
        AuditLogger(str(audit_path), policy_fingerprint=cfg.policy_fingerprint)
        if audit_path is not None
        else None
    )
    return AetheryaGateway(settings, constitution=constitution, cfg=cfg, audit=audit)


def check_actor_is_known(matrix: Any, actor: str, phase: int) -> None:
    """
    An actor missing from the capability matrix is denied on every call.

    In phase 1 and 2 that is invisible — `deny` is not enforced — so the
    misconfiguration would sit there until phase 3 turned the agent into a
    brick. Fail at startup in the phase where it matters, warn in the ones
    where it does not.
    """
    if not matrix.enabled or matrix.default_allow or actor in matrix.actors:
        return

    known = ", ".join(sorted(matrix.actors)) or "none"
    message = (
        f"actor {actor!r} is not in capability_matrix.actors (known: {known}). "
        f"Every action from this gateway will be denied. Add it under "
        f"capability_matrix.actors in your policy, or pass --actor."
    )
    if phase >= 3:
        raise ValueError(message)
    sys.stderr.write(f"[gateway] WARNING: {message}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aetherya-gateway",
        description="OpenAI-compatible endpoint that rules on every tool call before the agent sees it",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--provider", default=os.getenv("AETHERYA_GATEWAY_PROVIDER", "anthropic"))
    parser.add_argument("--model", default=os.getenv("AETHERYA_GATEWAY_MODEL", "claude-opus-5"))
    parser.add_argument("--actor", default=os.getenv("AETHERYA_GATEWAY_ACTOR", "openclaw"))
    parser.add_argument("--phase", type=int, default=None)
    parser.add_argument("--policy-path", type=Path, default=Path("config/policy.yaml"))
    parser.add_argument("--constitution-path", type=Path, default=None)
    parser.add_argument("--audit-path", type=Path, default=Path("audit/decisions.jsonl"))
    parser.add_argument("--effort", default="high", help="Anthropic only: output_config.effort")
    args = parser.parse_args(argv)

    cfg = load_policy_config(args.policy_path)
    phase = args.phase if args.phase is not None else cfg.enforcement.phase

    gateway = build_gateway(
        policy_path=args.policy_path,
        constitution_path=args.constitution_path,
        audit_path=args.audit_path,
        settings=GatewaySettings(
            provider=args.provider,
            model=args.model,
            actor=args.actor,
            phase=phase,
            anthropic_effort=args.effort,
        ),
    )

    server = build_gateway_server(args.host, args.port, gateway=gateway)
    sys.stderr.write(
        f"[gateway] {args.provider}/{args.model} · phase {phase} ({gateway.phase.name}) "
        f"· http://{args.host}:{args.port}/v1\n"
    )
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        sys.stderr.write(
            "[gateway] WARNING: bound to a non-loopback address. This process holds "
            "your upstream API key and answers unauthenticated requests.\n"
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
