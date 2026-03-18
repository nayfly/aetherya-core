# ÆTHERYA — Documentation Index

ÆTHERYA is a deterministic policy engine that enforces action governance for LLM-driven agents.
It sits between a proposed tool call and its execution, evaluating the action against constitutional constraints, risk signals, and optional human approval — then returns a verifiable decision.

---

## Mental model

```
Input          →  parser          (typed ActionRequest: intent, tool, actor, params)
Policy         →  constitution    (principle evaluation: keyword + optional semantic)
Risk           →  aggregation     (weighted signals → score → decision threshold)
Decision       →  allow / deny / escalate
Execution      →  external system (never inside ÆTHERYA)
Audit          →  verification    (JSONL, decision_id, context_hash, chain integrity)
```

---

## Position in the stack

ÆTHERYA sits between LLM output (proposed action) and system execution.

```
LLM → proposes tool call
      ↓
   ÆTHERYA  ←── policy.yaml, constitution, actor matrix
      ↓
   allow | deny | escalate
      ↓
   your execution layer
```

**ÆTHERYA is:**
- A deterministic action-governance layer for tool-calling agents
- A fail-closed safety boundary (any internal exception → deny)
- A verifiable audit trail (tamper-evident, chain-linked decisions)

**ÆTHERYA is not:**
- A model or LLM
- A firewall or WAF
- A full agent framework or orchestrator
- An OPA replacement (different abstraction level — action semantics, not HTTP/RBAC)

---

## Documentation map

| File | What it covers |
|------|---------------|
| [architecture.md](./architecture.md) | Pipeline stages, component roles, fail-closed guarantee, design principles |
| [security-model.md](./security-model.md) | Threat model, JailbreakGuard unicode normalization, confirmation + replay protection, audit chain |
| [policy-model.md](./policy-model.md) | Modes (consultive/operative), Constitution layers, semantic thresholds, policy.yaml structure |
| [parser-and-input-boundary.md](./parser-and-input-boundary.md) | How raw text becomes an ActionRequest, operative signal priority, structured input format |
| [output-gate.md](./output-gate.md) | Response safety guard, PII/secrets detection, `require_candidate_response` contract |
| [api.md](./api.md) | HTTP API endpoints, service modes (all/decision/approvals), curl examples |
| [integrations.md](./integrations.md) | Python integration patterns, CLI usage, agent runtime integration, OpenAI shadow |
| [testing-and-benchmarks.md](./testing-and-benchmarks.md) | Test suites, coverage gate, latency SLOs, chaos/stress/fuzz benchmarks |
| [release-and-verification.md](./release-and-verification.md) | Security gate (3-phase), release artifact verification, audit chain verification, explainability |

---

## Starting points

- **Integrate ÆTHERYA into your agent** → [integrations.md](./integrations.md)
- **Understand the pipeline** → [architecture.md](./architecture.md)
- **Configure policy thresholds** → [policy-model.md](./policy-model.md)
- **Run the confirmation/approval flow** → [security-model.md](./security-model.md#confirmation-and-approval-flow)
- **Run the HTTP API** → [api.md](./api.md)
- **Run tests** → [testing-and-benchmarks.md](./testing-and-benchmarks.md)
