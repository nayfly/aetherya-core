# Policy Model

## Modes

ÆTHERYA runs in one of two modes, configured in `config/policy.yaml`:

| Mode | `deny_at` | `confirm_at` | Use case |
|------|-----------|--------------|----------|
| `consultive` | 90 | 60 | Conservative — deny is rare |
| `operative` | 80 | 50 | Default for tool-use agents |

Mode is resolved per-request from the parsed `ActionRequest.mode_hint`.

---

## Constitution

Evaluates actions against defined principles using a hybrid two-layer architecture.

**Principles (default, configurable via `--constitution-path`):**
- `PromptSafety`
- `Non-harm`
- `DataProtection`
- `SystemIntegrity`

**Layer 1 — `FastKeywordEvaluator`** (always runs):
- Deterministic keyword matching with contextual negation detection (5-token lookback)
- Blocks obviously harmful inputs immediately (`confidence=0.9`, no model needed)
- Marks short/ambiguous inputs for semantic escalation
- SLO: **p95 ≤ 10ms**

**Layer 2 — `SemanticEvaluator`** (only for ambiguous inputs when `use_semantic=True`):
- Lazy-loaded `sentence-transformers/all-MiniLM-L6-v2` embeddings (no download on import)
- Falls back to degraded fast result if model is unavailable
- SLO: **p95 ≤ 150ms**

Default mode (`use_semantic=False`) is fully backward-compatible and requires no model download.

Returns structured signals: `risk_score`, `reason`, `tags`, `violated_principle`.

---

## Semantic Thresholds

Configurable in `policy.yaml` under `constitution`:

```yaml
constitution:
  semantic_violation_threshold: 0.55   # cosine similarity → violation
  semantic_gray_zone_threshold: 0.35   # cosine similarity → gray zone (risk × 0.6)
```

- `> violation_threshold` → violation signal
- `gray_zone_threshold – violation_threshold` range → gray zone, risk dampened
- `< gray_zone_threshold` → clean

Validation: `violation_threshold` must be in `(0.0, 1.0]`; `gray_zone_threshold` must be in `[0.0, violation_threshold)`.

---

## Risk Aggregation

Signals from all guards and the constitution are merged by the `RiskAggregator`:
- Weighted scoring (weights configurable in `policy.yaml` under `aggregator.weights`)
- Hard-deny tags bypass the score entirely and always result in DENY:
  - `critical_tag_detected`
  - `jailbreak_attempt`
  - `tool_not_allowed`
  - `capability_tool_denied`

---

## policy.yaml Structure

Key sections:

```yaml
mode: operative           # or: consultive

policy:
  deny_at: 80
  confirm_at: 50

aggregator:
  hard_deny_if:
    - critical_tag_detected
    - jailbreak_attempt
    - tool_not_allowed
    - capability_tool_denied
  weights:
    execution_gate: 1.0
    capability_gate: 1.0
    jailbreak_guard: 1.0
    procedural_guard: 1.0
    constitution: 1.0

constitution:
  semantic_violation_threshold: 0.55
  semantic_gray_zone_threshold: 0.35

output_gate:
  require_candidate_response: false

confirmation:
  evidence:
    signed_proof:
      enabled: false
      replay_mode: single_use
      replay_store: memory

llm_shadow:
  enabled: false
  provider: dry_run
```

---

## OpenAI Shadow Mode

Shadow-only — never affects the decision.

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

Safety contract: OpenAI runs after the decision is made. `allowed` is never overridden. Output stored under `context.llm_shadow` in the audit log as `shadow_suggestion` + `ethical_divergence`.
