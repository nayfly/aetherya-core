from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aetherya.api import AetheryaAPI, APISettings


class RequestTooLargeError(ValueError):
    pass


def _dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AETHERYA API Dashboard</title>
  <style>
    :root {
      --bg-a: #f8fbff;
      --bg-b: #eef7f2;
      --panel: #ffffff;
      --ink: #122029;
      --muted: #53636d;
      --line: #d8e2e8;
      --accent: #0d8c77;
      --accent-strong: #0a705f;
      --danger: #bb1f3a;
      --shadow: 0 10px 30px rgba(17, 45, 58, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "Trebuchet MS", "Gill Sans", "Segoe UI", sans-serif;
      background: radial-gradient(circle at 15% 10%, var(--bg-b), var(--bg-a) 60%);
      min-height: 100vh;
    }
    .wrap {
      max-width: 1040px;
      margin: 0 auto;
      padding: 28px 18px 36px;
    }
    .hero {
      background: linear-gradient(135deg, #0d8c77, #207a9f);
      color: #f7ffff;
      border-radius: 16px;
      padding: 18px 20px;
      box-shadow: var(--shadow);
      margin-bottom: 18px;
    }
    .hero h1 {
      margin: 0 0 6px;
      font-size: 1.4rem;
      letter-spacing: 0.2px;
    }
    .hero p {
      margin: 0;
      opacity: 0.95;
      font-size: 0.96rem;
    }
    .grid {
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      box-shadow: var(--shadow);
    }
    .panel h2 {
      margin: 0 0 10px;
      font-size: 1rem;
    }
    label {
      display: block;
      margin: 8px 0 4px;
      color: var(--muted);
      font-size: 0.88rem;
      font-weight: 700;
      letter-spacing: 0.2px;
      text-transform: uppercase;
    }
    input, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fbfdff;
      color: var(--ink);
      font: inherit;
      padding: 9px 10px;
    }
    textarea {
      min-height: 90px;
      resize: vertical;
    }
    .row {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .check {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.9rem;
      color: var(--muted);
      text-transform: none;
      margin: 0;
      font-weight: 600;
    }
    .check input { width: auto; }
    button {
      border: 0;
      border-radius: 10px;
      background: var(--accent);
      color: #fff;
      padding: 9px 13px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: transform 120ms ease, background 120ms ease;
    }
    button:hover { background: var(--accent-strong); transform: translateY(-1px); }
    button:active { transform: translateY(0); }
    pre {
      margin: 0;
      background: #0f1c24;
      color: #d8eaf3;
      border-radius: 12px;
      border: 1px solid #1f3441;
      padding: 12px;
      min-height: 220px;
      overflow: auto;
      font-size: 0.84rem;
      line-height: 1.4;
    }
    .status {
      margin-left: auto;
      font-size: 0.84rem;
      color: var(--muted);
      font-weight: 700;
    }
    .status.err { color: var(--danger); }
    .hint {
      margin-top: 6px;
      color: var(--muted);
      font-size: 0.84rem;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>AETHERYA API Dashboard</h1>
      <p>Interactive panel for health checks, policy decisions, signed approvals, and audit-chain verification.</p>
    </section>

    <section class="grid">
      <article class="panel">
        <h2>Health</h2>
        <div class="row">
          <button id="btn-health" type="button">GET /health</button>
          <span class="status" id="health-status">idle</span>
        </div>
        <p class="hint">Quick runtime check: policy, fingerprint and defaults.</p>
      </article>

      <article class="panel">
        <h2>Decide</h2>
        <label for="decide-raw">raw_input</label>
        <textarea id="decide-raw">help user safely</textarea>
        <label for="decide-actor">actor</label>
        <input id="decide-actor" type="text" value="robert">
        <label for="decide-response">candidate_response (optional)</label>
        <textarea id="decide-response" placeholder="Generated user-facing answer to validate with OutputGate"></textarea>
        <div class="row">
          <label class="check"><input id="decide-wait-shadow" type="checkbox" checked>wait_shadow</label>
          <button id="btn-decide" type="button">POST /v1/decide</button>
          <span class="status" id="decide-status">idle</span>
        </div>
      </article>

      <article class="panel">
        <h2>Confirmation Sign (Admin)</h2>
        <label for="sign-raw">raw_input</label>
        <textarea id="sign-raw">mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write param.confirm_token=ack:abc12345 param.confirm_context=approved_by_operator</textarea>
        <label for="sign-actor">actor</label>
        <input id="sign-actor" type="text" value="robert">
        <label for="sign-ttl">expires_in_sec (optional)</label>
        <input id="sign-ttl" type="text" value="60">
        <label for="sign-admin">x-aetherya-admin-key</label>
        <input id="sign-admin" type="password" placeholder="admin key for human-only signing">
        <div class="row">
          <button id="btn-sign" type="button">POST /v1/confirmation/sign</button>
          <span class="status" id="sign-status">idle</span>
        </div>
      </article>

      <article class="panel">
        <h2>Confirmation Verify (Admin)</h2>
        <label for="verify-proof-raw">raw_input</label>
        <textarea id="verify-proof-raw">mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write param.confirm_token=ack:abc12345 param.confirm_context=approved_by_operator</textarea>
        <label for="verify-proof-actor">actor</label>
        <input id="verify-proof-actor" type="text" value="robert">
        <label for="verify-proof-value">approval_proof</label>
        <input id="verify-proof-value" type="text" placeholder="ap1.kid.exp.nonce.scope_hash.sig">
        <label for="verify-admin">x-aetherya-admin-key</label>
        <input id="verify-admin" type="password" placeholder="admin key for human-only verify">
        <div class="row">
          <button id="btn-proof-verify" type="button">POST /v1/confirmation/verify</button>
          <span class="status" id="proof-verify-status">idle</span>
        </div>
      </article>

      <article class="panel">
        <h2>Audit Verify</h2>
        <div class="row">
          <label class="check"><input id="verify-chain" type="checkbox" checked>require_chain</label>
          <label class="check"><input id="verify-hmac" type="checkbox">require_hmac</label>
        </div>
        <label for="verify-index">event_index (optional)</label>
        <input id="verify-index" type="text" placeholder="-1">
        <div class="row">
          <button id="btn-verify" type="button">POST /v1/audit/verify</button>
          <span class="status" id="verify-status">idle</span>
        </div>
      </article>
    </section>

    <section class="panel" style="margin-top:14px;">
      <h2>Response</h2>
      <pre id="response-view">{\n  "ok": true,\n  "message": "Ready"\n}</pre>
    </section>
  </div>

  <script>
    const view = document.getElementById("response-view");
    const setStatus = (id, text, isErr = false) => {
      const el = document.getElementById(id);
      el.textContent = text;
      el.classList.toggle("err", isErr);
    };
    const render = (data) => {
      view.textContent = JSON.stringify(data, null, 2);
    };
    const request = async (statusId, url, body = null, extraHeaders = null) => {
      setStatus(statusId, "loading...", false);
      try {
        const opts = body === null ? {} : {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(extraHeaders || {}),
          },
          body: JSON.stringify(body),
        };
        const res = await fetch(url, opts);
        const data = await res.json();
        render({ http_status: res.status, ...data });
        setStatus(statusId, `HTTP ${res.status}`, !res.ok);
        return { res, data };
      } catch (err) {
        render({ ok: false, error_type: "NetworkError", error: String(err) });
        setStatus(statusId, "network error", true);
        return null;
      }
    };

    document.getElementById("btn-health").addEventListener("click", () => {
      request("health-status", "/health", null);
    });

    document.getElementById("btn-decide").addEventListener("click", () => {
      const candidateResponse = document.getElementById("decide-response").value.trim();
      const payload = {
        raw_input: document.getElementById("decide-raw").value,
        actor: document.getElementById("decide-actor").value,
        wait_shadow: document.getElementById("decide-wait-shadow").checked,
      };
      if (candidateResponse) {
        payload.candidate_response = candidateResponse;
      }
      request("decide-status", "/v1/decide", {
        ...payload,
      });
    });

    document.getElementById("btn-sign").addEventListener("click", async () => {
      const ttlRaw = document.getElementById("sign-ttl").value.trim();
      const adminKey = document.getElementById("sign-admin").value.trim();
      const payload = {
        raw_input: document.getElementById("sign-raw").value,
        actor: document.getElementById("sign-actor").value,
      };
      if (ttlRaw) {
        const ttl = Number(ttlRaw);
        payload.expires_in_sec = Number.isInteger(ttl) ? ttl : ttlRaw;
      }
      const result = await request(
        "sign-status",
        "/v1/confirmation/sign",
        payload,
        adminKey ? { "X-AETHERYA-Admin-Key": adminKey } : {}
      );
      if (result && result.data && result.data.approval_proof) {
        document.getElementById("verify-proof-value").value = result.data.approval_proof;
      }
    });

    document.getElementById("btn-proof-verify").addEventListener("click", () => {
      const adminKey = document.getElementById("verify-admin").value.trim();
      const payload = {
        raw_input: document.getElementById("verify-proof-raw").value,
        actor: document.getElementById("verify-proof-actor").value,
        approval_proof: document.getElementById("verify-proof-value").value,
      };
      request(
        "proof-verify-status",
        "/v1/confirmation/verify",
        payload,
        adminKey ? { "X-AETHERYA-Admin-Key": adminKey } : {}
      );
    });

    document.getElementById("btn-verify").addEventListener("click", () => {
      const rawIndex = document.getElementById("verify-index").value.trim();
      const payload = {
        require_chain: document.getElementById("verify-chain").checked,
        require_hmac: document.getElementById("verify-hmac").checked,
      };
      if (rawIndex) {
        const n = Number(rawIndex);
        payload.event_index = Number.isInteger(n) ? n : rawIndex;
      }
      request("verify-status", "/v1/audit/verify", payload);
    });
  </script>
</body>
</html>
"""


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

    def _handle_request(self) -> None:
        method = self.command.upper()
        path = urlsplit(self.path).path
        if method == "GET" and path in {"/", "/dashboard"}:
            self._send_html(200, _dashboard_html())
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
) -> None:
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
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
