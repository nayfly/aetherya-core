# Changelog

All notable changes to this project are documented in this file.

## Unreleased

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
- CI now runs an audit attestation self-check after test coverage using strict HMAC verification.
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

### Changed
- CI workflow now runs `security_gate` in a dedicated job and enforces tag release readiness (`v*`) via `release_readiness` depending on `test` + `security_gate`.
- CI `test` job now executes versioned security baseline regression on every push/PR.

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
