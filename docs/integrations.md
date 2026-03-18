# Integrations

## Position in the stack

ÆTHERYA is a **decision boundary**, not an orchestrator or LLM.
You call it before executing any sensitive tool action and branch on the result:

```
LLM proposes action
      ↓
  api.decide(raw_input, actor)        ← ÆTHERYA
      ↓
  decision.allowed == True  → execute tool
  decision.state == "escalate"        → request human approval → sign proof → retry
  decision.allowed == False           → surface reason, do not execute
```

It does not call tools, does not orchestrate agents, and does not block non-sensitive operations.

---

## Minimum real integration

The smallest correct integration using real project contracts:

```python
from pathlib import Path
from aetherya.api import APISettings, AetheryaAPI

api = AetheryaAPI(
    APISettings(
        policy_path=Path("config/policy.yaml"),
        audit_path=Path("audit/decisions.jsonl"),
    )
)

status, payload = api.decide({
    "raw_input": "mode:operative tool:filesystem target:/tmp param.path=/tmp/out.txt param.operation=write",
    "actor": "robert",
    "wait_shadow": False,
})

decision = payload.get("decision", {})
# decision keys: allowed (bool), state (str), reason (str), risk_score (int),
#                violated_principle (str|None), mode (str), abi_version (str)

if status == 200 and decision.get("allowed"):
    # Execute tool here
    pass
else:
    # decision["state"]: "deny" | "hard_deny" | "escalate" | "log_only"
    # decision["reason"]: human-readable explanation
    raise PermissionError(f"{decision.get('state')}: {decision.get('reason')}")
```

**Decision states:**
| `state` | `allowed` | Meaning |
|---------|-----------|---------|
| `allow` | `True` | Proceed |
| `log_only` | `True` | Proceed — consultive mode, event logged for review |
| `escalate` | `False` | Requires human approval or signed proof |
| `deny` | `False` | Policy violation — do not execute |
| `hard_deny` | `False` | Critical violation — unconditional block |

---

## Wrap-a-tool pattern

The idiomatic way to use ÆTHERYA is to wrap each sensitive tool in a function that enforces the decision contract:

```python
from pathlib import Path
from aetherya.api import APISettings, AetheryaAPI

api = AetheryaAPI(
    APISettings(
        policy_path=Path("config/policy.yaml"),
        audit_path=Path("audit/decisions.jsonl"),
    )
)


def safe_delete(path: str, actor: str, proof: str | None = None) -> str:
    """
    Wraps a delete operation behind ÆTHERYA.
    Raises PermissionError if the decision is not allowed.
    When signed_proof is enabled in policy, a valid proof is required.
    """
    raw = (
        f"mode:operative tool:filesystem target:{path}"
        f" param.path={path} param.operation=delete"
        f" param.confirm_token=ack:del123"
        f" param.confirm_context=operator_approved"
    )
    if proof:
        raw += f" param.confirm_proof={proof}"

    _, response = api.decide({"raw_input": raw, "actor": actor, "wait_shadow": False})
    decision = response.get("decision", {})

    if not decision.get("allowed"):
        raise PermissionError(
            f"Denied: {decision.get('reason')}  (state={decision.get('state')})"
        )

    # Execute real operation here
    return f"deleted {path}"
```

Usage:

```python
# Allowed
safe_delete("/tmp/workfile.txt", actor="robert")

# Denied → PermissionError raised
safe_delete("/etc/passwd", actor="robert")
```

For a runnable end-to-end example including the signed proof flow, see [`examples/basic_tool_wrapper.py`](../examples/basic_tool_wrapper.py).

---

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
  2. Serialize to raw_input string  →  api.decide({"raw_input": ..., "actor": ...})
  3. decision["allowed"] == True            → execute tool
     decision["state"]  == "escalate"       → request human approval → sign proof → retry
     decision["allowed"] == False           → surface reason to LLM or user, do not execute
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
