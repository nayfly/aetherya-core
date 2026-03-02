# Changelog

All notable changes to this project are documented in this file.

## Unreleased

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
  - deterministic HMAC proof format (`ap1.<expires_at>.<nonce>.<signature>`)
  - action-bound scope hashing (`actor` + tool/operation/target/params)
  - policy-configurable proof verification window and clock skew guards
  - optional `signed_proof` confirmation policy block (`enabled`, `proof_param`, `key_env`)
  - new CLI command: `aetherya confirmation sign` to mint proofs for interactive/ops workflows

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
