# Changelog

All notable changes to this project are documented in this file.

## Unreleased

## v0.8.0 - 2026-03-11

### Security

- `Parser`: operative content now takes unconditional priority over question framing. Inputs containing an operative verb (`run`, `execute`, `delete`, `send`, `curl`, `docker`, `rm`) or an explicit `tool:` field are classified as `intent=operate / mode=operative` regardless of whether they start with a question word or end with `?`. Previously, question framing could downgrade an operationally active input to `mode=consultive`, applying looser risk thresholds. Question heuristic now applies only to inputs with zero operative signals.
- `JailbreakGuard`: text is now Unicode-normalized before pattern matching (NFKD decomposition + stripping of combining chars and Unicode format characters — category `Cf`). This eliminates bypass via zero-width spaces (U+200B), zero-width joiners (U+200C/D), BOM (U+FEFF), diacritic insertion, and fullwidth character substitution.
- `JailbreakGuard`: multilingual pattern corpus added — Spanish, French, German. Covers role override, policy override, instruction suppression, and prompt exfiltration patterns in each language. Post-normalization matching handles accented variants without separate patterns.
- `JailbreakGuard`: all matching patterns are now collected before returning instead of stopping at first match. Complete tag list is preserved in the audit trace for telemetry and explainability.
- `OutputGate`: extended PII pattern coverage — AWS Access Key ID (`AKIA[0-9A-Z]{16}`), JWT tokens (three base64url segments), PEM private key blocks (`-----BEGIN * PRIVATE KEY-----`), Anthropic API keys (`sk-ant-`), and phone numbers (US/E.164 with structural separators). `sk-ant-` pattern checked before generic `sk-` to ensure correct categorization.
- `OutputGate`: new `output_gate.require_candidate_response` policy flag (default `false`). When set to `true`, `run_pipeline` fails-closed at stage `output_gate_required` if `response_text` is not provided, making output protection a hard enforcement rather than an opt-in.

### Added

- `config.py`: `OutputGateConfig` dataclass with `require_candidate_response` field. Loaded from `policy.yaml` under `output_gate` key.
- `config.py`: `ConstitutionConfig` dataclass with `semantic_violation_threshold` (default `0.55`) and `semantic_gray_zone_threshold` (default `0.35`) fields. Loaded from `policy.yaml` under `constitution` key. Both values validated on load: violation threshold must be in `(0.0, 1.0]`, gray zone must be in `[0.0, violation_threshold)`.
- `policy.yaml`: explicit `output_gate` and `constitution` sections with documented defaults and contract notes.
- `Constitution` and `SemanticEvaluator`: accept `semantic_violation_threshold` and `semantic_gray_zone_threshold` constructor parameters (backward-compatible, defaults preserved).
- `ActorRateLimiter`: explicit docstring documenting single-process safeguard scope and multi-process limitation.

### Fixed

- `Parser`: inputs like `"Can you delete all logs?"` or `"What does rm -rf do?"` were incorrectly classified as `intent=ask / mode=consultive` despite containing operative verbs. These now correctly resolve to `intent=operate / mode=operative`.
- `SemanticEvaluator`: violation and gray-zone thresholds were hardcoded at `0.55` / `0.35` with no external configuration point.

### Documentation

- README split into focused pages under `docs/`: `architecture.md`, `security-model.md`, `policy-model.md`, `parser-and-input-boundary.md`, `output-gate.md`, `api.md`, `integrations.md`, `testing-and-benchmarks.md`, `release-and-verification.md`.
- `docs/index.md` added as primary documentation entry point — project overview, mental model, position in stack, and doc map.
- `docs/integrations.md` expanded with "Where ÆTHERYA sits", "What ÆTHERYA does not do", wrap-a-tool pattern, and decision state reference table.
- `examples/basic_tool_wrapper.py` added — runnable end-to-end example of wrapping sensitive tools using real `AetheryaAPI` contracts. Demonstrates deny, allow, escalate, signed proof, and replay rejection.
- `examples/agent_integration.py` added — simulated agent loop showing ÆTHERYA as the decision boundary between a proposed tool call and execution. Covers allow, block, hard_deny, and jailbreak cases.
- `examples/policy.minimal.yaml` added — self-contained policy file for examples; no dependency on repo root CWD.
- `assets/demo.gif` added — terminal recording of `agent_integration.py` embedded in README.

### Compatibility Notes

- `PolicyConfig` gains two new optional fields with defaults: `output_gate_config: OutputGateConfig` and `constitution_config: ConstitutionConfig`. Existing callers constructing `PolicyConfig` directly must add these if not using keyword arguments, or migrate to `load_policy_config`.
- `Constitution.__init__` gains two new optional keyword parameters with defaults: `semantic_violation_threshold=0.55`, `semantic_gray_zone_threshold=0.35`. Existing callers are unaffected.
- Parser behavior change: inputs combining question framing with operative verbs now resolve to `operate/operative` instead of `ask/consultive`. Any tests or downstream logic relying on the old behavior must be updated.

## v0.7.0 - 2026-03-11

### Added
- Constitution: hybrid two-layer evaluation architecture (`FastKeywordEvaluator` + `SemanticEvaluator`).
- Constitution: contextual negation detection in `FastKeywordEvaluator` — 5-token lookback window with single negators (`not`, `no`, `never`, `without`, `avoid`, `prevent`) and multi-word phrases (`how to stop`, `how to prevent`).
- Constitution: semantic evaluation layer using `sentence-transformers/all-MiniLM-L6-v2` with lazy model loading (no download on import).
- Constitution: `use_semantic` parameter (default `False`, fully backward-compatible); semantic layer activates only on ambiguous short inputs.
- `SemanticEvaluator`: cosine similarity thresholds — `>0.55` full violation, `0.35–0.55` gray zone (risk × 0.6), `<0.35` clean.
- `OutputGate`: PII and secrets detection — email addresses, credit card numbers (plain and formatted), OpenAI API keys (`sk-`), GitHub tokens (`ghp_`), Slack tokens (`xox[baprs]-`), Bearer tokens, Spanish DNI/NIE, and IBAN ES numbers. Returns `risk_score=85`, `confidence=0.9`, `violated_principle="DataPrivacy"`.
- `JailbreakGuard`: 16 new paraphrase-based patterns across 4 categories:
  - `ignore_instructions_paraphrase` — set aside/overlook/discard instructions, pay no attention to, pretend no rules, forget guidelines
  - `role_override_paraphrase` — pretend you are, act as if you were, simulate being, roleplay as unrestricted, you are now
  - `policy_override_paraphrase` — respond without restrictions, answer freely, no limitations, uncensored/unrestricted mode
  - `prompt_exfiltration_paraphrase` — repeat your instructions, what were you told, show me your prompt, display your system
- `Parser`: question detection — `intent=ask` is set for interrogative inputs (starts with a question word or ends with `?`) when no operative signals are present, preventing misclassification of purely informational queries as `intent=operate`.
- `ActorRateLimiter`: sliding-window per-actor rate limiting with `threading.Lock` and configurable `requests_per_window` / `window_seconds` (`RateLimitConfig`). Integrated as optional step in `run_pipeline()`.
- CI: new `semantic_slo` job with HuggingFace model cache, real-model slow test execution, and semantic pipeline benchmark (SLO: p95 ≤ 150ms, p99 ≤ 200ms).
- CI: `release_readiness` now also requires `semantic_slo` to pass on tag releases.
- `pytest.mark.slow` marker with `--run-slow` opt-in flag (via `conftest.py`) to skip model-download tests by default.

### Fixed
- Constitution: false positives from keyword matching without semantic context — negation-aware evaluation prevents blocking queries like "how to prevent delete accidents".
- `JailbreakGuard`: trivial bypasses via paraphrasing not covered by original literal patterns.
- `pipeline._call_with_timeout`: thread leak on timeout — manual `threading.Event` + daemon thread replaced with `concurrent.futures.ThreadPoolExecutor` + `shutdown(wait=False)`.

### Changed
- Pipeline latency SLO split into two profiles: fast-path (p95 ≤ 10ms, no model) and semantic-path (p95 ≤ 150ms, with embeddings).
- `pipeline_benchmark.py`: added `--use-semantic` flag for differentiated SLO benchmarks.
- `pyproject.toml`: added `sentence-transformers>=2.7.0` and `numpy>=1.26.0` as runtime dependencies.

## v0.6.0 - 2026-03-02

### Added
- Added unified CLI entrypoint scaffold (`aetherya`) with initial `decide` command.
- Added `aetherya decide` features:
  - positional/flag/stdin input support
  - optional `--constitution-path` loader (YAML/JSON)
  - optional `--audit-path` logging output
  - `--wait-shadow` / `--no-wait-shadow` toggle (default waits)
  - JSON/text output with execution metadata
- Added CLI wrapper subcommands that forward to existing module CLIs:
  - `aetherya audit verify`
  - `aetherya explainability render/report`
  - `aetherya security gate/baseline`
  - `aetherya release verify-artifacts`
  - `aetherya benchmark pipeline/chaos`
- Added real OpenAI shadow provider integration via `OpenAILLMProvider` (`OPENAI_API_KEY`, lazy SDK import, timeout support).
- Added config surface for LLM shadow provider selection and transport controls:
  - `llm_shadow.provider` (`dry_run`/`openai`)
  - `llm_shadow.timeout_sec`
- Added OpenAI shadow regression tests to verify:
  - provider contract mapping to `LLMResponse`
  - pipeline `shadow-only` authority (no impact on core `allowed` decision)
  - fail-safe behavior when OpenAI provider initialization fails
- Added CLI regression tests for `decide` behavior (`stdin`, constitution loading, shadow wait toggle, conflicting input handling).
- Added CLI routing tests for wrapper argument forwarding and nested command validation.
- Added reusable real-provider smoke test script:
  - `scripts/openai_shadow_smoke.py`
  - `make openai_shadow_smoke`
- Added final pre-API CLI devil gate script:
  - `scripts/pre_api_gate.py`
  - `make pre_api_gate`
  - validates actor spoofing fail-closed behavior, shadow timeout resilience, and audit chain integrity/tamper detection in one command.
- Added native HTTP API stack (no extra runtime dependency):
  - `aetherya.api` service layer with routes:
    - `GET /health`
    - `POST /v1/decide`
    - `POST /v1/audit/verify`
  - `aetherya.api_server` threaded HTTP server entrypoint (`aetherya-api`)
  - browser dashboard for human operators (`GET /`, `GET /dashboard`)
  - explicit `405 MethodNotAllowed` responses on POST-only routes when called via GET
  - `make api_serve` convenience target
  - end-to-end server tests + service-level contract tests
- Added deterministic `OutputGate` for response safety:
  - new `output_gate` module for toxic/insulting response detection
  - optional `response_text` path in pipeline (`run_pipeline(..., response_text=...)`)
  - `output_gate` signal integration in risk aggregation + audit context
  - API/CLI support via optional `candidate_response`
  - fail-closed stage for output validation errors (`fail_closed:output_gate`)
- Added out-of-band confirmation proof support for sensitive operations:
  - deterministic HMAC proof format (`ap1.<kid>.<expires_at>.<nonce>.<scope_hash>.<signature>`)
  - action-bound scope hashing (`actor` + tool/operation/target/params)
  - policy-configurable proof verification window and clock skew guards
  - optional `signed_proof` confirmation policy block (`enabled`, `proof_param`, `key_env`, `keyring_env`, `active_kid`, `replay_mode`)
  - new CLI command: `aetherya confirmation sign` to mint proofs for interactive/ops workflows
- Added replay protection for signed confirmation proofs in `ConfirmationGate`:
  - in-memory TTL nonce store
  - `single_use` and `idempotent` modes
  - deterministic replay-rejection reasons/tags in decision trace
- Added Redis-backed replay store option for signed confirmation proofs:
  - policy flag: `confirmation.evidence.signed_proof.replay_store` (`memory`/`redis`)
  - env-configurable Redis endpoint and key namespace:
    - `replay_redis_url_env`
    - `replay_redis_prefix`
  - atomic anti-replay writes with `SET NX EX`
  - centralized replay protection across processes/workers
  - optional dependency group: `redis` (`pip install -e ".[redis]"`)
- Added admin-protected confirmation API routes:
  - `POST /v1/confirmation/sign`
  - `POST /v1/confirmation/verify`
  - localhost-only by default + `X-AETHERYA-Admin-Key` check (`AETHERYA_APPROVALS_API_KEY`)
- Added API route-profile split for physical separation of decision and approvals surfaces:
  - `--service-mode all|decision|approvals`
  - new entrypoints:
    - `aetherya-decision-server`
    - `aetherya-approvals-server`
  - route exposure is now explicit per process profile.

### Changed
- `run_pipeline` now selects `llm_shadow` provider from policy config and records `provider_configured` in audit context.
- README now documents `OpenAI` shadow mode setup and safety contract.
- README architecture section now matches actual deterministic `run_pipeline` execution order and fail-closed behavior.
- Added optional dependency group `llm` with `openai>=1.0.0`.

## v0.5.0 - 2026-03-01

### Added
- Added `policy_decision_adapter` module with a decoupled integration contract for future external intelligence providers (LLM/vector retrieval):
  - `PolicyDecisionRequest` / `PolicyDecisionResponse`
  - `PolicySignalCandidate` / `PolicyDecisionCandidate`
  - `PolicyDecisionAdapter` protocol + deterministic `DryRunPolicyDecisionAdapter`
- Added `security_baseline` CLI (`python -m aetherya.security_baseline`) for deterministic, versioned stress regression checks against:
  - jailbreak adversarial/benign baseline metrics
  - audit tamper/integrity baseline metrics
- Added versioned stress baseline snapshot at `tests/fixtures/security_baseline/v1/stress_baseline.json`.
- Added `make security_baseline` single-command local/CI entrypoint for baseline validation.
- Added pipeline integration for `policy_adapter_shadow` telemetry:
  - runs `DryRunPolicyDecisionAdapter` in non-blocking mode
  - emits projected-risk and adapter signal trace into audit context
- Added chaos tests:
  - concurrent byte mutation campaign against `audit/decisions.jsonl` while `AuditLogger` writes, with detection latency assertion (`<10ms`)
  - corrupt signal-type injection test to assert immediate `fail_closed:risk_aggregate`
- Added `chaos_benchmark` CLI (`python -m aetherya.chaos_benchmark`) to run repeated deterministic chaos campaigns and emit latency metrics + SLO verdict (`p95`/`p99`).
- Added `make chaos_benchmark` local command to generate `audit/chaos/chaos_benchmark_metrics.json`.
- Added `verify_release_artifacts` CLI (`python -m aetherya.verify_release_artifacts`) for strict release manifest attestation checks (`HMAC`, `commit_sha`, `decision_count`, phase1 audit line count).
- Added `pipeline_benchmark` CLI (`python -m aetherya.pipeline_benchmark`) for deterministic normal-operation latency SLO checks on a 100-input corpus.
- Added `make pipeline_benchmark` local command to generate `audit/pipeline/pipeline_benchmark_metrics.json`.
- Added randomized property tests for `RiskAggregator` under extreme/edge signal values.
- Added release-artifact fuzz campaign tests (64-round corruption scenarios) for manifest/audit hardening.
- Added `scripts/pipeline_memory_soak.py` + `make pipeline_memory_soak` to run 10-minute leak-oriented RSS monitoring loops.
- Added `make property_tests` and `make audit_fuzz` convenience targets for pre-release stress validation.
- Added explicit `llm_shadow` audit fields:
  - `shadow_suggestion` (dry-run textual suggestion + projected state/risk)
  - `ethical_divergence` (state mismatch and risk delta vs core decision)

### Changed
- CI workflow now runs `security_gate` in a dedicated job and enforces tag release readiness (`v*`) via `release_readiness` depending on `test` + `security_gate`.
- CI `test` job now executes versioned security baseline regression on every push/PR.
- CI now runs `chaos_tests` as a separate job with artifact upload and latency thresholds (`p95<=12ms`, `p99<=20ms`, detection rate `1.0`).
- CI now runs `pipeline_slo` as a dedicated latency gate (`p95<=10ms`, `p99<=15ms`) over deterministic pipeline benchmark inputs.
- `release_readiness` no longer trusts upstream success only; it now downloads `security_gate` artifacts and performs strict cryptographic/content validation before passing.
- `verify_release_artifacts` now rejects invalid UTF-8 and non-object/invalid JSON lines in phase1 audit artifacts.

## v0.4.0 - 2026-02-28

### Added
- `explainability_render` CLI (`python -m aetherya.explainability_render`) to export audit explainability graphs to Mermaid.
- `explainability_report` CLI (`python -m aetherya.explainability_report`) to export static HTML audit reports.
- cryptographic decision attestation in audit events:
  - `hmac-sha256` when attestation key is configured
  - deterministic `sha256` fallback when key is absent
- `llm_shadow` pipeline mode with dry-run provider telemetry (`usage`, `request_hash`, `finish_reason`) without action execution.
- `audit_verify` CLI (`python -m aetherya.audit_verify`) to validate `context_hash`, `decision_id` and attestation for one event or full JSONL.
- `audit_verify --require-hmac` strict mode to reject non-`hmac-sha256` audit events.
- `audit_verify --require-chain` to validate `prev_chain_hash`/`chain_hash` causal integrity across full JSONL.
- CI audit attestation self-check after test coverage using strict HMAC verification.
- Added stress suites:
  - high-volume audit integrity verification with sparse tampering detection
  - high-volume jailbreak adversarial/benign regression and pipeline blocking checks
- Added versioned security corpus fixtures at `tests/fixtures/security_corpus/v1` for realistic attack/benign regressions.
- Added deterministic tamper campaign with lightweight mutation strategies (swap IDs, reorder windows, signature corruption, chain corruption).
- Added `security_gate` CLI (`python -m aetherya.security_gate`) implementing:
  - Phase 1 corpus regression against expected decision snapshots
  - Phase 2 deterministic integrity fuzz campaign (1,000-event default)
  - Phase 3 signed release manifest generation (HMAC)
- `security_gate` supports optional `--failure-report-dir` to emit explainability HTML for failing corpus cases.

## v0.3.0 - 2026-02-28

### Added
- `ExplainabilityEngine` with deterministic justification graph (`nodes`, `edges`, contributors with weights).
- `ExecutionGate` for tool/target/parameter contract enforcement in operative actions.
- `CapabilityGate` with actor/role/operation matrix and fail-closed behavior.
- `JailbreakGuard` with deterministic prompt-injection pattern detection.
- `ConfirmationGate` for strong confirmation (`confirm_token` + `confirm_context`) on sensitive operations.
- Deterministic audit traceability with `decision_id` and `context_hash`.
- Audit-level `policy_fingerprint` propagation for end-to-end policy provenance.
- Dry-run LLM provider contract:
  - `LLMProvider` protocol
  - `LLMRequest` / `LLMResponse` / `LLMUsage` contracts
  - `DryRunLLMProvider` deterministic implementation for local integration tests.

### Changed
- Pipeline now composes all gates in deterministic order with fail-closed behavior by stage.
- Runtime config validation hardened (unknown role references, invalid confirmation schema constraints).
- Coverage gate raised to `>=99%`.

### Quality
- Full regression suite expanded for execution/capability/jailbreak/confirmation and audit paths.
- Type-checking, linting, and coverage kept green at release cut.

### Compatibility Notes
- `PolicyConfig` now includes `policy_fingerprint`.
- Audit events now include `policy_fingerprint` and enrich context with policy provenance when available.
