# HTTP API

## Service Modes

| Mode | Routes | Default port |
|------|--------|-------------|
| `all` | decide + audit + approvals | 8080 |
| `decision` | `/health`, `/v1/decide`, `/v1/audit/verify` | 8080 |
| `approvals` | `/health`, `/v1/confirmation/sign`, `/v1/confirmation/verify` | 8081 |

Run:

```bash
# All-in-one
make api_serve
# or: aetherya-api --service-mode all --host 127.0.0.1 --port 8080

# Split — decision service
make api_decision_serve
# or: aetherya-decision-server --host 127.0.0.1 --port 8080

# Split — approvals service (localhost-only, requires admin key)
make api_approvals_serve
# or: aetherya-approvals-server --host 127.0.0.1 --port 8081
```

In split mode:
- decision service: no `AETHERYA_CONFIRMATION_HMAC_KEY*`
- approvals service: has signing keyring + admin key

---

## Endpoints

### `GET /health`

Returns policy load status and fingerprint.

```bash
curl -s http://127.0.0.1:8080/health
```

### `POST /v1/decide`

Main decision endpoint.

```bash
curl -s -X POST http://127.0.0.1:8080/v1/decide \
  -H "Content-Type: application/json" \
  -d '{
    "raw_input": "help user",
    "actor": "robert",
    "wait_shadow": true,
    "candidate_response": "Thank you for your question."
  }'
```

Request fields:
- `raw_input` — string (required)
- `actor` — string (required)
- `wait_shadow` — boolean, default `true`
- `candidate_response` — string, optional (OutputGate input)

Response:

```json
{
  "decision": {
    "allowed": true,
    "state": "ALLOW",
    "risk_score": 10,
    "reason": "...",
    "violated_principle": null,
    "mode": "consultive"
  },
  "context": { ... }
}
```

### `POST /v1/audit/verify`

Verifies audit chain integrity.

```bash
curl -s -X POST http://127.0.0.1:8080/v1/audit/verify \
  -H "Content-Type: application/json" \
  -d '{"require_chain": true, "require_hmac": false}'
```

### `POST /v1/confirmation/sign` (admin-only)

Signs an input with HMAC proof. Requires:
- `X-AETHERYA-Admin-Key` header matching `AETHERYA_APPROVALS_API_KEY`
- Localhost caller (`127.0.0.1` / `::1`)

```bash
export AETHERYA_APPROVALS_API_KEY="replace-with-admin-key"

curl -s -X POST http://127.0.0.1:8081/v1/confirmation/sign \
  -H "Content-Type: application/json" \
  -H "X-AETHERYA-Admin-Key: ${AETHERYA_APPROVALS_API_KEY}" \
  -d '{
    "raw_input": "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write param.confirm_token=ack:abc12345 param.confirm_context=approved_by_operator",
    "actor": "robert",
    "expires_in_sec": 60
  }'
```

### `POST /v1/confirmation/verify` (admin-only)

Verifies an existing approval proof. Same auth requirements as `/sign`.

```bash
curl -s -X POST http://127.0.0.1:8081/v1/confirmation/verify \
  -H "Content-Type: application/json" \
  -H "X-AETHERYA-Admin-Key: ${AETHERYA_APPROVALS_API_KEY}" \
  -d '{
    "raw_input": "...",
    "actor": "robert",
    "approval_proof": "<approval_proof>"
  }'
```

---

## Notes

- `GET /` and `GET /dashboard` serve an interactive dashboard for non-CLI users.
- `GET /v1/decide` and `GET /v1/audit/verify` return `405 Method Not Allowed` — use `POST`.
- Redis-backed replay protection (multi-process safe): set `confirmation.evidence.signed_proof.replay_store: redis` and export `AETHERYA_CONFIRMATION_REPLAY_REDIS_URL`. See [security-model.md](./security-model.md#confirmation-and-approval-flow).
