# Integrations

## Python (Direct API)

Minimal integration — no HTTP server needed:

```python
from pathlib import Path
from aetherya.api import APISettings, AetheryaAPI

api = AetheryaAPI(
    APISettings(
        policy_path=Path("config/policy.yaml"),
        audit_path=Path("audit/decisions.jsonl"),
        default_actor="robert",
    )
)

status, payload = api.decide({
    "raw_input": "mode:operative tool:filesystem target:/tmp param.path=/tmp/demo.txt param.operation=write",
    "actor": "robert",
    "wait_shadow": False,
})

decision = payload.get("decision", {})
if status == 200 and decision.get("allowed"):
    # Execute your tool here
    pass
else:
    # Escalate, ask for confirmation, or return safe fallback
    pass
```

### With OutputGate

Pass the candidate response to check for PII/toxic content before delivery:

```python
status, payload = api.decide({
    "raw_input": "help user",
    "actor": "robert",
    "candidate_response": "Your data is ready.",
    "wait_shadow": False,
})
```

---

## CLI

### Basic decision

```bash
aetherya decide "mode:operative tool:shell target:host-1 param.command=echo_ok run diagnostics" \
  --actor robert --json
```

### With custom constitution and audit path

```bash
aetherya decide "forbidden_token now" \
  --constitution-path config/constitution.yaml \
  --audit-path audit/decisions.jsonl \
  --json
```

### Validate candidate response

```bash
aetherya decide "help user" --candidate-response "you are an idiot" --json
```

### Disable shadow waiting (bulk automation)

```bash
aetherya decide "help user" --no-wait-shadow --json
```

### Out-of-band signed confirmation

```bash
export AETHERYA_CONFIRMATION_HMAC_KEY="replace-with-long-random-secret"

# Sign
aetherya confirmation sign \
  "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write param.confirm_token=ack:abc12345 param.confirm_context=approved_by_operator" \
  --actor robert --expires-in-sec 60 --json

# Decide with proof
aetherya decide \
  "mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write param.confirm_token=ack:abc12345 param.confirm_context=approved_by_operator param.confirm_proof=<approval_proof>" \
  --actor robert --json
```

### Unified subcommands

```bash
aetherya audit verify -- --audit-path audit/decisions.jsonl --require-hmac --require-chain --json
aetherya explainability render -- --audit-path audit/decisions.jsonl --event-index -1
aetherya explainability report -- --audit-path audit/decisions.jsonl --event-index -1 --output audit/explainability_report.html
aetherya security gate -- --json
aetherya security baseline -- --json
aetherya release verify-artifacts -- --expected-commit-sha "$(git rev-parse HEAD)" --json
aetherya benchmark pipeline -- --runs 1 --corpus-size 100 --json
aetherya benchmark chaos -- --runs 25 --events 48 --json
```

Note: use `--` before forwarded flags for maximum compatibility in shell automation.

---

## Agent Runtimes

ÆTHERYA is a decision boundary, not an orchestrator. Integrate it as a gate before any sensitive tool execution:

```
Agent loop:
  1. LLM proposes tool call
  2. Serialize to raw_input string  →  aetherya.decide(raw_input, actor)
  3. if allowed → execute tool
     if require_confirm → request human approval → sign proof → retry with proof
     if deny → surface reason to LLM or user
```

For long-running pipelines, use the HTTP API (`/v1/decide`) so the policy engine runs as an independent service. See [api.md](./api.md).

---

## OpenAI Shadow Mode

Shadow telemetry — runs after the decision, never affects `allowed`.

Enable in `policy.yaml`:

```yaml
llm_shadow:
  enabled: true
  provider: openai
  model: gpt-4o-mini
  temperature: 0.0
  max_tokens: 96
  timeout_sec: 10.0
```

Requirements:
- `OPENAI_API_KEY` exported
- `pip install -e ".[dev,llm]"`

Output stored under `context.llm_shadow` in the audit log:
- `shadow_suggestion` — what the LLM would have said
- `ethical_divergence` — delta between shadow and core decision

Smoke script: `scripts/openai_shadow_smoke.py`

---

## Installation

```bash
# Base + dev tools
pip install -e ".[dev]"

# With OpenAI shadow
pip install -e ".[dev,llm]"

# With Redis replay store
pip install -e ".[dev,redis]"
```

Semantic evaluation (`use_semantic=True` in Constitution) is included in the base install — uses `sentence-transformers/all-MiniLM-L6-v2`, lazy-loaded on first use.
