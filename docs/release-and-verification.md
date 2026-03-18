# Release and Verification

## Quality Gates (CI)

| Job | Trigger | SLOs / Checks |
|-----|---------|---------------|
| `test` | every push | pytest --cov, coverage ≥ 99%, mypy clean, ruff + black |
| `security_gate` | every push | 3-phase release gate (see below) |
| `chaos_tests` | every push | p95 ≤ 12ms, p99 ≤ 20ms, detection rate = 1.0 |
| `pipeline_slo` | every push | p95 ≤ 10ms, p99 ≤ 15ms (100-input corpus) |
| `semantic_slo` | every push | p95 ≤ 150ms, p99 ≤ 200ms (50-input corpus, cached model) |
| `release_readiness` | tag `v*` | requires `test` + `security_gate` to pass; validates signed manifest |

---

## Security Gate (3-Phase Release Gate)

**Phase 1** — corpus regression against expected snapshots
**Phase 2** — deterministic integrity fuzz campaign (1,000 events)
**Phase 3** — signed release manifest

```bash
AETHERYA_ATTESTATION_KEY="your-key" python -m aetherya.security_gate \
  --phase2-events 1000 \
  --phase2-seed 1337 \
  --phase2-mutation-rounds 32
```

Optional HTML failure reports:

```bash
AETHERYA_ATTESTATION_KEY="your-key" python -m aetherya.security_gate \
  --failure-report-dir audit/security_gate/fail_reports
```

---

## Release Artifact Verification

`release_readiness` validates the signed `security_manifest.json`:
- manifest must be present and non-empty
- HMAC signature must be valid
- `commit_sha` must match the release commit
- `decision_count` must match expected corpus size and phase1 audit line count

Manual verification:

```bash
AETHERYA_ATTESTATION_KEY="your-key" \
GITHUB_SHA="$(git rev-parse HEAD)" \
python -m aetherya.verify_release_artifacts \
  --manifest-path audit/security_gate/security_manifest.json \
  --phase1-audit-path audit/security_gate/phase1_corpus_audit.jsonl
```

CLI wrapper:

```bash
aetherya release verify-artifacts -- \
  --expected-commit-sha "$(git rev-parse HEAD)" --json
```

---

## Audit Chain Verification

Verify integrity (`context_hash`, `decision_id`) and cryptographic attestation:

```bash
# Basic integrity check
python -m aetherya.audit_verify --audit-path audit/decisions.jsonl

# Single event, JSON output
python -m aetherya.audit_verify --audit-path audit/decisions.jsonl --event-index -1 --json

# Strict HMAC (rejects non-HMAC events)
AETHERYA_ATTESTATION_KEY="your-key" python -m aetherya.audit_verify \
  --audit-path audit/decisions.jsonl --require-hmac

# Strict chain-causality (detects reordered/sabotaged JSONL history)
AETHERYA_ATTESTATION_KEY="your-key" python -m aetherya.audit_verify \
  --audit-path audit/decisions.jsonl --require-hmac --require-chain
```

CLI wrapper:

```bash
aetherya audit verify -- --audit-path audit/decisions.jsonl --require-hmac --require-chain --json
```

---

## Explainability

Generate Mermaid graph from the latest audit event:

```bash
# Print to stdout
python -m aetherya.explainability_render --audit-path audit/decisions.jsonl --event-index -1

# Write to file
python -m aetherya.explainability_render \
  --audit-path audit/decisions.jsonl --event-index -1 \
  --output audit/explainability_latest.mmd
```

Generate static HTML report (summary + Mermaid graph):

```bash
python -m aetherya.explainability_report \
  --audit-path audit/decisions.jsonl \
  --event-index -1 \
  --output audit/explainability_report.html \
  --title "AETHERYA Audit Report"
```

CLI wrapper:

```bash
aetherya explainability render -- --audit-path audit/decisions.jsonl --event-index -1
aetherya explainability report -- --audit-path audit/decisions.jsonl --event-index -1 \
  --output audit/explainability_report.html
```

---

## Versioned Security Baseline

Validates deterministic stress metrics against a versioned snapshot at `tests/fixtures/security_baseline/v1/stress_baseline.json`:
- JailbreakGuard attack/benign regression rates
- Audit integrity tamper detection baseline
- Deterministic fuzz campaign mismatch profile

```bash
make security_baseline
```

See [testing-and-benchmarks.md](./testing-and-benchmarks.md) for full test suite documentation.
