# Testing and Benchmarks

## Running Tests

```bash
# All fast tests with coverage
pytest --cov

# Include slow tests (sentence-transformers model download)
pytest --run-slow

# Single file / single test
pytest tests/test_foo.py
pytest tests/test_foo.py::test_bar
```

Coverage gate: `fail_under = 99` (enforced in CI and locally via `pytest --cov`).

---

## Test Suites

### Stress and security regression

```bash
pytest tests/test_audit_integrity_stress.py \
       tests/test_audit_tamper_campaign.py \
       tests/test_jailbreak_guard_stress.py \
       tests/test_security_corpus_regression.py -q
```

### Versioned security baseline

Validates deterministic stress metrics against a versioned snapshot:
- JailbreakGuard attack/benign regression rates
- Audit integrity tamper detection baseline
- Deterministic fuzz campaign mismatch profile

```bash
make security_baseline
# or:
python -m aetherya.security_baseline \
  --baseline-path tests/fixtures/security_baseline/v1/stress_baseline.json
```

Update snapshot intentionally:

```bash
python -m aetherya.security_baseline --update-baseline
```

### Chaos tests

```bash
pytest tests/test_audit_chaos_bytes.py tests/test_pipeline_policy_adapter_shadow.py -q
```

### LLM shadow tests

```bash
pytest tests/test_llm_provider.py tests/test_pipeline_llm_shadow.py -q
```

---

## Benchmarks

### Pipeline latency SLO (fast path, no semantic model)

Corpus: 100 inputs. SLOs:
- `p95 ≤ 10ms`
- `p99 ≤ 15ms`

```bash
make pipeline_benchmark
# or: aetherya benchmark pipeline -- --runs 1 --corpus-size 100 --json
```

### Chaos benchmark

SLOs:
- `p95 ≤ 12ms`
- `p99 ≤ 20ms`
- detection rate = `1.0`

```bash
make chaos_benchmark
# or: aetherya benchmark chaos -- --runs 25 --events 48 --json
```

Each run uploads `audit/chaos/chaos_benchmark_metrics.json` as a CI artifact.

### Semantic SLO (with HuggingFace model)

Corpus: 50 inputs. SLOs:
- `p95 ≤ 150ms`
- `p99 ≤ 200ms`

Run with `pytest --run-slow` or via the dedicated CI job (`semantic_slo`, which caches the model).

---

## Additional Suites

### Property / extreme tests

```bash
make property_tests
```

Randomized tests over `RiskAggregator` + chaos paths.

### Release artifact fuzzing

```bash
make audit_fuzz
```

Phase-2 mutation round over release artifacts.

### Memory soak

10-minute memory soak over repeated pipeline benchmark loops:

```bash
make pipeline_memory_soak
```

### Pre-API gate

Final smoke test before API deployment (actor spoofing, shadow timeout, chain integrity):

```bash
make pre_api_gate
```

Report written to: `audit/pre_api/pre_api_gate_report.json`.

### OpenAI shadow smoke

Real provider, authority invariance check:

```bash
make openai_shadow_smoke
```

---

## Full Check

Format + lint + type + coverage:

```bash
make check
```

Individual steps:

```bash
make fmt    # ruff + black
make lint   # ruff --fix
make type   # mypy src/aetherya
```
