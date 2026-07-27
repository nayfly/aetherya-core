from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from aetherya.api import AetheryaAPI, APISettings
from aetherya.config import load_policy_config
from aetherya.console import console_html
from aetherya.constitution import warmup_semantic_model


class RequestTooLargeError(ValueError):
    pass


class AetheryaHTTPRequestHandler(BaseHTTPRequestHandler):
    api: AetheryaAPI | None = None
    max_body_bytes: int = 1_048_576

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_json_body(self) -> dict[str, Any]:
        raw_content_length = self.headers.get("Content-Length", "").strip()
        if not raw_content_length:
            return {}
        try:
            content_length = int(raw_content_length)
        except ValueError as exc:
            raise ValueError("invalid Content-Length header") from exc

        if content_length < 0:
            raise ValueError("invalid Content-Length header")
        if content_length == 0:
            return {}
        if content_length > self.max_body_bytes:
            raise RequestTooLargeError(
                f"request body too large: {content_length} > {self.max_body_bytes}"
            )

        raw_body = self.rfile.read(content_length)
        if not raw_body:
            return {}
        try:
            decoded = raw_body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("request body must be utf-8") from exc
        try:
            payload = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise ValueError("request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _query(self) -> dict[str, Any]:
        raw = parse_qs(urlsplit(self.path).query)
        return {key: values[0] for key, values in raw.items() if values}

    def _handle_request(self) -> None:
        method = self.command.upper()
        path = urlsplit(self.path).path
        if method == "GET" and path in {"/", "/console", "/dashboard"}:
            self._send_html(200, console_html())
            return

        # Read-only console data. Gated behind AETHERYA_CONSOLE_API_KEY when it
        # is set; open otherwise, like the rest of the decision profile. This
        # view exposes every recorded action, so the port must not be public.
        if method == "GET" and path in {"/v1/decisions", "/v1/rollout/report"}:
            if self.api is None:
                self._send_json(500, {"ok": False, "error": "api not configured"})
                return
            expected = os.getenv("AETHERYA_CONSOLE_API_KEY", "").strip()
            if expected:
                provided = self.headers.get("X-AETHERYA-Console-Key", "").strip()
                if not provided or not hmac.compare_digest(provided, expected):
                    self._send_json(
                        401,
                        {
                            "ok": False,
                            "error_type": "Unauthorized",
                            "error": "missing or invalid console key",
                        },
                    )
                    return
            query = self._query()
            status, body = (
                self.api.decisions(query) if path == "/v1/decisions" else self.api.rollout(query)
            )
            self._send_json(status, body)
            return

        payload: dict[str, Any] = {}
        if method == "POST":
            try:
                payload = self._parse_json_body()
            except RequestTooLargeError as exc:
                self._send_json(
                    413,
                    {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
                )
                return
            except ValueError as exc:
                self._send_json(
                    400,
                    {"ok": False, "error_type": type(exc).__name__, "error": str(exc)},
                )
                return

        if self.api is None:
            self._send_json(
                500,
                {
                    "ok": False,
                    "error_type": "RuntimeError",
                    "error": "api service is not configured",
                },
            )
            return

        status, response = self.api.dispatch(
            method=method,
            path=path,
            payload=payload,
            headers={str(k): str(v) for k, v in self.headers.items()},
            client_ip=str(self.client_address[0]) if self.client_address else None,
        )
        self._send_json(status, response)

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_request()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return None


def _build_handler(
    api: AetheryaAPI,
    *,
    max_body_bytes: int,
) -> type[AetheryaHTTPRequestHandler]:
    class _BoundHandler(AetheryaHTTPRequestHandler):
        pass

    _BoundHandler.api = api
    _BoundHandler.max_body_bytes = max_body_bytes
    return _BoundHandler


def build_server(
    host: str,
    port: int,
    *,
    api: AetheryaAPI,
    max_body_bytes: int,
) -> ThreadingHTTPServer:
    handler = _build_handler(api, max_body_bytes=max_body_bytes)
    return ThreadingHTTPServer((host, port), handler)


def warmup_semantic_layer(
    *,
    policy_path: Path,
    warmup_semantic: bool = True,
    require_semantic_ready: bool = False,
) -> bool:
    """
    Preload the semantic model before the server accepts traffic.

    With `require_warm_semantic_model` the advisory layer declines to run on a
    cold model, so without this a long-lived server would answer every request
    with the layer silently inactive. Doing it at startup keeps the multi-second
    load out of the decision path entirely.

    Returns True when the layer is ready. When it is not and
    `require_semantic_ready` is set, startup fails rather than serving in a
    degraded state that only /health would reveal.
    """
    cfg = load_policy_config(policy_path)
    if not (cfg.constitution_config.use_semantic and warmup_semantic):
        return False

    try:
        warmup_semantic_model()
        return True
    except Exception as exc:
        if require_semantic_ready:
            raise RuntimeError(
                f"semantic layer requested but unavailable: {type(exc).__name__}: {exc}"
            ) from exc
        print(
            f"warning: semantic warmup failed ({type(exc).__name__}: {exc}); "
            "the advisory layer will be skipped — /health reports degraded=true",
            file=sys.stderr,
        )
        return False


def serve_api(
    *,
    host: str,
    port: int,
    policy_path: Path,
    audit_path: Path | None,
    constitution_path: Path | None,
    default_actor: str,
    max_body_bytes: int,
    service_name: str = "aetherya-api",
    enable_decide_routes: bool = True,
    enable_audit_routes: bool = True,
    enable_approval_routes: bool = True,
    warmup_semantic: bool = True,
    require_semantic_ready: bool = False,
) -> None:
    warmup_semantic_layer(
        policy_path=policy_path,
        warmup_semantic=warmup_semantic,
        require_semantic_ready=require_semantic_ready,
    )

    settings = APISettings(
        policy_path=policy_path,
        audit_path=audit_path,
        constitution_path=constitution_path,
        default_actor=default_actor,
        service_name=service_name,
        enable_decide_routes=enable_decide_routes,
        enable_audit_routes=enable_audit_routes,
        enable_approval_routes=enable_approval_routes,
    )
    api = AetheryaAPI(settings)
    server = build_server(
        host=host,
        port=port,
        api=api,
        max_body_bytes=max_body_bytes,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AETHERYA HTTP API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--policy-path", default="config/policy.yaml")
    parser.add_argument("--audit-path", default="audit/decisions.jsonl")
    parser.add_argument("--constitution-path", default=None)
    parser.add_argument("--default-actor", default="robert")
    parser.add_argument("--max-body-bytes", type=int, default=1_048_576)
    parser.add_argument(
        "--no-warmup-semantic",
        action="store_true",
        help=(
            "Skip preloading the semantic model at startup. The advisory layer "
            "then stays inactive until something warms it; /health reports "
            "degraded=true."
        ),
    )
    parser.add_argument(
        "--require-semantic-ready",
        action="store_true",
        help=(
            "Fail startup if the semantic layer is enabled in policy but cannot "
            "be loaded, instead of serving in a degraded state."
        ),
    )
    parser.add_argument(
        "--service-mode",
        choices=["all", "decision", "approvals"],
        default="all",
        help="Route profile: all, decision-only, or approvals-only.",
    )
    args = parser.parse_args(argv)

    try:
        if args.port <= 0 or args.port > 65535:
            raise ValueError("port must be between 1 and 65535")
        if args.max_body_bytes <= 0:
            raise ValueError("max-body-bytes must be > 0")

        mode = str(args.service_mode).strip().lower()
        service_name = {
            "all": "aetherya-api",
            "decision": "aetherya-decision",
            "approvals": "aetherya-approvals",
        }[mode]
        enable_decide_routes = mode in {"all", "decision"}
        enable_audit_routes = mode in {"all", "decision"}
        enable_approval_routes = mode in {"all", "approvals"}

        serve_api(
            host=str(args.host),
            port=int(args.port),
            policy_path=Path(str(args.policy_path)),
            audit_path=Path(str(args.audit_path)) if args.audit_path else None,
            constitution_path=Path(str(args.constitution_path)) if args.constitution_path else None,
            default_actor=str(args.default_actor),
            max_body_bytes=int(args.max_body_bytes),
            service_name=service_name,
            enable_decide_routes=enable_decide_routes,
            enable_audit_routes=enable_audit_routes,
            enable_approval_routes=enable_approval_routes,
            warmup_semantic=not bool(args.no_warmup_semantic),
            require_semantic_ready=bool(args.require_semantic_ready),
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
