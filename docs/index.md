# ÆTHERYA — Documentation Index

ÆTHERYA is a deterministic policy engine that decides whether a proposed agent action should be allowed, denied, or escalated before it reaches any external system.

---

## What it does

```
LLM / agent proposes a tool call
           ↓
       ÆTHERYA
    ┌──────────────────────────────────┐
    │  parse → guard chain → constitution → risk → confirmation │
    └──────────────────────────────────┘
           ↓
  allow | deny | hard_deny | escalate
           ↓
  your execution layer (or nothing)
```

ÆTHERYA **is:**
- A deterministic action-governance layer for tool-calling agents
- A fail-closed safety boundary (any internal exception → deny)
- A verifiable audit trail (tamper-evident, chain-linked decisions)

ÆTHERYA **is not:**
- A model or LLM
- A firewall or WAF
- A full agent framework or orchestrator
- An OPA replacement (different abstraction level — action semantics, not HTTP/RBAC)

---

## Where it sits

```
Agent loop:
  1. LLM proposes action
  2. → ÆTHERYA evaluates        ← this is the insertion point
  3. allowed=True  → execute
     state=escalate → request human approval → retry with proof
     allowed=False  → block, surface reason
```

See a runnable simulation: [`examples/agent_integration.py`](../examples/agent_integration.py)

---

## Documentation

| File | What it covers |
|------|----------------|
| [integrations.md](./integrations.md) | How to integrate — Python, CLI, agent loop, wrap-a-tool pattern |
| [architecture.md](./architecture.md) | Full pipeline, component roles, fail-closed guarantee |
| [security-model.md](./security-model.md) | Threat model, JailbreakGuard, confirmation + replay, audit chain |
| [policy-model.md](./policy-model.md) | Modes, Constitution, semantic thresholds, policy.yaml structure |
| [parser-and-input-boundary.md](./parser-and-input-boundary.md) | How raw text becomes an ActionRequest, operative signal priority |
| [output-gate.md](./output-gate.md) | Response safety, PII/secrets detection, require_candidate_response |
| [api.md](./api.md) | HTTP API endpoints, service modes, curl examples |
| [testing-and-benchmarks.md](./testing-and-benchmarks.md) | Test suites, coverage gate, latency SLOs, benchmarks |
| [release-and-verification.md](./release-and-verification.md) | Security gate, audit verification, release artifacts |
