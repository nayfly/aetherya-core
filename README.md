# ÆTHERYA – Deterministic Ethical Decision Core

![CI](https://github.com/nayfly/aetherya-core/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Version](https://img.shields.io/badge/version-0.8.0-informational)

A deterministic, risk-aware policy engine that sits between an LLM and any sensitive action.

---

## Problem

Without a control boundary, agent runtimes become:

```
LLM → tool call → irreversible action
```

## Solution

ÆTHERYA inserts a deterministic decision boundary:

```
LLM → policy/gates/confirmation → allow | deny | escalate → execution
```

---

## This repository is / is not

**Is:**
- A deterministic policy kernel for action governance
- A verifiable audit layer (`decision_id`, `context_hash`, chain integrity)
- A fail-closed safety boundary for agent tool execution

**Is not:**
- An LLM serving stack
- A replacement for your agent runtime or orchestrator
- A business workflow engine

---

## Quickstart

```bash
pip install -e ".[dev]"

# Evaluate an action
aetherya decide "help user safely" --actor robert --json

# Verify audit-chain integrity
python -m aetherya.audit_verify --audit-path audit/decisions.jsonl --require-chain --json
```

---

## Pipeline (simplified)

```
Input → Parser → RateLimiter → ExecutionGate → CapabilityGate
      → JailbreakGuard → ProceduralGuard → Constitution
      → RiskAggregator → ConfirmationGate → PolicyEngine → Decision
      → Explainability → Audit
```

Fail-closed: any exception in any stage → `allowed=false`.

---

## Approval Demo (DENY → SIGN → ALLOW → REPLAY DENY → AUDIT OK)

Prerequisites: Redis running locally, `pip install -e ".[dev,redis]"`.

```bash
export AETHERYA_CONFIRMATION_HMAC_KEY="demo-key-v06"
export AETHERYA_CONFIRMATION_REPLAY_REDIS_URL="redis://127.0.0.1:6379/0"

POLICY=/tmp/policy_demo_v06.yaml
AUDIT=/tmp/aetherya_demo_v06.jsonl
RAW='mode:operative tool:filesystem target:/tmp param.path=/tmp/demo.txt param.operation=write param.confirm_token=ack:abc12345 param.confirm_context=approved_by_operator'

python - <<'PY'
from pathlib import Path
import yaml
data = yaml.safe_load(Path("config/policy.yaml").read_text())
sp = data["confirmation"]["evidence"]["signed_proof"]
sp["enabled"] = True
sp["replay_store"] = "redis"
sp["replay_redis_url_env"] = "AETHERYA_CONFIRMATION_REPLAY_REDIS_URL"
sp["replay_redis_prefix"] = "aetherya:appr"
Path("/tmp/policy_demo_v06.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
PY

# 1) No proof → DENY
aetherya decide "$RAW" --actor robert --policy-path "$POLICY" --audit-path "$AUDIT" --json \
  | python -c 'import sys,json; d=json.load(sys.stdin); print("1)", d["decision"]["allowed"], d["decision"]["state"])'

# 2) Sign
SIGN="$(aetherya confirmation sign "$RAW" --actor robert --policy-path "$POLICY" --expires-in-sec 60 --json)"
PROOF="$(printf '%s' "$SIGN" | python -c 'import sys,json; print(json.load(sys.stdin)["approval_proof"])')"

# 3) With proof → ALLOW
aetherya decide "$RAW param.confirm_proof=$PROOF" --actor robert --policy-path "$POLICY" --audit-path "$AUDIT" --json \
  | python -c 'import sys,json; d=json.load(sys.stdin); print("3)", d["decision"]["allowed"], d["decision"]["state"])'

# 4) Replay → DENY
aetherya decide "$RAW param.confirm_proof=$PROOF" --actor robert --policy-path "$POLICY" --audit-path "$AUDIT" --json \
  | python -c 'import sys,json; d=json.load(sys.stdin); print("4)", d["decision"]["allowed"], d["decision"]["state"], "-", d["decision"]["reason"])'

# 5) Audit chain
python -m aetherya.audit_verify --audit-path "$AUDIT" --require-chain --json \
  | python -c 'import sys,json; d=json.load(sys.stdin); print("5)", "AUDIT OK" if d["invalid"]==0 else "AUDIT FAIL")'
```

---

## Documentation

| Topic | Link |
|-------|------|
| Architecture & pipeline | [docs/architecture.md](docs/architecture.md) |
| Security model & threat model | [docs/security-model.md](docs/security-model.md) |
| Policy model & constitution | [docs/policy-model.md](docs/policy-model.md) |
| Parser & input boundary | [docs/parser-and-input-boundary.md](docs/parser-and-input-boundary.md) |
| OutputGate & PII detection | [docs/output-gate.md](docs/output-gate.md) |
| HTTP API | [docs/api.md](docs/api.md) |
| Integrations (Python, CLI, agents) | [docs/integrations.md](docs/integrations.md) |
| Testing & benchmarks | [docs/testing-and-benchmarks.md](docs/testing-and-benchmarks.md) |
| Release & verification | [docs/release-and-verification.md](docs/release-and-verification.md) |

---

`v0.8.0` — See [CHANGELOG.md](./CHANGELOG.md) for release details.
