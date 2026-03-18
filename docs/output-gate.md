# OutputGate (Response Safety)

## Purpose

Optional deterministic guard that evaluates the candidate user-facing response **before delivery**. Prevents toxic output and data leakage from reaching the user.

Runs as the last signal-generating stage, after the decision pipeline but before the final audit write.

---

## Configuration

In `policy.yaml`:

```yaml
output_gate:
  require_candidate_response: false
```

In the pipeline call:

```python
status, payload = api.decide({
    "raw_input": "...",
    "actor": "robert",
    "candidate_response": "The file has been deleted.",
})
```

CLI:

```bash
aetherya decide "help user" --candidate-response "you are an idiot" --json
```

---

## `require_candidate_response` Contract

When `require_candidate_response: true` in `policy.yaml`:
- Calling `run_pipeline` **without** `candidate_response` → `fail_closed:output_gate` (escalate, `allowed=false`)
- This enforces that integrators cannot silently skip the output check

When `false` (default):
- If no `candidate_response` is provided, the gate is skipped silently
- Responsibility falls on the integrator to pass the response when needed

---

## PII and Secrets Detection

The gate emits a `DataPrivacy` signal (`risk_score=85`) when any of these patterns are detected:

| Pattern | Label |
|---------|-------|
| Email addresses | `email` |
| Credit card numbers (Luhn groups) | `credit_card` |
| `sk-ant-*` API keys (Anthropic) | `api_key` |
| `sk-*` API keys (generic) | `api_key` |
| `ghp_*` GitHub personal access tokens | `api_key` |
| `xox[baprs]-*` Slack tokens | `api_key` |
| Bearer tokens | `api_key` |
| AWS AKIA access keys | `aws_access_key` |
| JWT tokens (`eyJ...eyJ...`) | `jwt_token` |
| PEM private key blocks | `private_key` |
| Phone numbers (US/E.164 with separators) | `phone_number` |
| Spanish DNI/NIE | `spanish_id` |
| IBAN ES numbers | `iban` |

---

## Toxic Content Detection

Emits an `OutputSafety` signal when toxic or insulting terms are detected in the response text.

---

## Audit Evidence

On every evaluation, the gate stores in the audit context:
- `response_hash` — SHA-256 of the candidate response
- `response_length` — character count

---

## Limitations

- Pattern-based detection: does not understand semantic context
- No language-specific tokenization — regex operates on raw text
- `require_candidate_response` is opt-in by design; default is permissive to avoid breaking existing integrations
- False positives possible for legitimate technical content (e.g., documentation containing key examples)
