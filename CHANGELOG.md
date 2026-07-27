# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Fixed (CI)

- `examples/agent_loop.py`: the OpenAI backend checked for the SDK before checking for the API key, so the error you got depended on whether `openai` happened to be installed. It is present in a dev environment and absent from CI's `[dev]` extra, which is exactly why `test_openai_backend_requires_a_key` passed locally and failed CI on the last two pushes. The key is now checked first — a missing key is the more common misconfiguration, and you should not need the SDK installed to be told about it — and both paths have tests, one of which blocks the import to prove it.
- `security_gate` phase 2 generates its own corpus but `AuditLogger` appends by design, so a file left by a previous local run was appended to and counted. The phase then failed on events it had not created, reporting `invalid == total`, which reads like a real integrity regression. CI never saw it (fresh checkout) but a second local run always did. The phase now starts from a clean file and is idempotent, with a test asserting two consecutive runs both pass.

### Fixed (found while containerising)

- **The HTTP API never applied the configured rate limit.** `rate_limit` was validated at load and `build_rate_limiter()` had 13 integration tests, but nothing in the API path ever constructed a limiter — the configured limit was documentation, not behaviour. `AetheryaAPI` now builds one per process (rebuilt only when the policy's rate-limit section changes; rebuilding per request would reset every window and make it a no-op) and passes it to the pipeline. Verified end to end through the container: 65 requests from one actor against a limit of 60 yielded 60 allowed and 5 refused, with the window visible in Redis.
- `run_pipeline` typed `rate_limiter` as `ActorRateLimiter`, so the Redis backend could not be passed to it at all. Widened to the `RateLimiter` protocol — mypy caught this the moment the API tried to wire it up.

### Added (containerised local stack)

- `Dockerfile` — two-stage build, non-root user, the semantic model baked in at build time (with `require_warm_semantic_model`, downloading it on first boot would either delay readiness or leave the advisory layer silently inactive). Healthcheck asserts `ok && !degraded && policy_fingerprint_match`, so a replica serving under an unintended policy or with the advisory layer inert is not marked healthy.
- `docker-compose.yml` — decision service plus Redis, with the audit chain on a named volume so it survives the container. Verified: chain intact across a restart (9 events, 0 invalid). The approvals service is deliberately absent — it is localhost-only by design and belongs to phase 3, not phase 1.
- `config/policy.docker.yaml` — deployment policy, identical to `config/policy.yaml` except for the distributed rate-limit backend. The repo default stays `memory` because `redis` fails closed and would refuse every request without a reachable server. A test pins the two files to differ in exactly that one field so they cannot drift.

### Added (rollout)

- `docs/rollout-phases.md` — the three-phase production rollout as an executable plan: shadow, hard-deny enforcement, full enforcement. Each phase states its posture, the wiring change it needs, what to measure, and **exit criteria that can fail**, including what to do when shadow mode reports an unacceptable false-positive rate. Also documents the target operating configuration and the `/health` readiness gate.
- `examples/agent_loop.py` — a real agent loop with the engine as the execution boundary, switchable between the three phases (`--phase 1|2|3`). The existing example showed the API call but not what an agent is; this one runs the loop: the model proposes a tool call, the engine rules on it, and the result *or the refusal* goes back into the conversation. Two backends: a deterministic scripted agent (no API key, no network, reproducible) and a real OpenAI tool-calling loop (`--agent openai`) — the gating code around them is identical, which is the property being demonstrated. The scenario is a prompt injection arriving through tool output rather than a malicious model, so the boundary is doing the work the model cannot.
- `examples/policy.minimal.yaml`: synchronised with the current `config/policy.yaml` rule families and given a `demo-agent` actor.

### Fixed (review follow-up)

- **Rate limiter eviction could reset a throttled actor's window.** Verified exploitable, not just an overstated docstring: a throttled client backs off — correct client behaviour — which makes it the least-recently-used entry, so plain LRU dropped it first and its limit reset. An attacker could lift a victim's throttle by flooding distinct actor ids (measured: 2 000 junk actors restored a blocked actor to `allowed`). Windows at or above the limit are now never evicted; when no evictable window remains a *new* actor is refused instead (fail-closed) and counted in `capacity_refusals`. The previous claim that "active actors are never displaced" was stronger than the algorithm guaranteed and has been replaced with what it actually does.
- **The policy pin compared file bytes, not behaviour.** `policy_fingerprint` is sha256 over the YAML's exact bytes, which is wrong in both directions: reformatting or editing comments rejected a behaviourally identical policy, and — the case that matters — a code upgrade changing a *default* left the file untouched, so the fingerprint was unchanged while the engine decided differently. That is exactly the silent divergence the pin exists to catch. New `effective_fingerprint` hashes the loaded configuration with all defaults resolved, and the pin is checked against it. `policy_fingerprint` is retained for provenance ("which file did this replica load"). Both are exposed on `/health` and by the new `aetherya policy fingerprint`.
- `HTTPAuditSink`: fixed a deadlock introduced in the same change — `stats()` held the stats lock and called `healthy()`, which took the non-reentrant lock again, while `pending()` acquired the queue lock in the opposite order to `write()`. Lock order is now one-directional (queue → stats) with no nested acquisition, and there is a regression test that hammers both paths concurrently.
- `HTTPAuditSink.close()` flushed a single batch, so shutting down with a backlog silently lost the tail of the audit trail. It now drains.

### Added (review follow-up)

- **Real-Redis integration suite** (`tests/integration/`, marker `integration`, `AETHERYA_TEST_REDIS_URL`) with a `redis:7-alpine` service container in CI. The in-memory double could not demonstrate MULTI/EXEC semantics, serialization between concurrent clients, real TTL, or that separate limiter instances share state. Covers 50 and 100 concurrent threads granting exactly N permits, actor isolation under concurrency, window expiry and recovery, throttled retries not extending the window, bounded TTL, shared reset, connection recovery after pool disconnect, real connection failure, and the pipeline path. Validated against Redis 6.2.14: a deliberately racy read-then-write implementation granted **92 permits against a limit of 10** under 100 threads where the shipped implementation granted exactly 10 — the test discriminates.
- **Concrete durable audit sinks.** `HTTPAuditSink` (batched, background worker, bounded queue with oldest-drop, retry with backoff) ships byte-identical lines to any HTTP ingest endpoint; `FileAuditSink` mirrors to a second path. A protocol alone did not close the retention gap — an implementation does.
- **Mirror observability.** `/health` reports `audit_mirror_configured`, `audit_mirror_ok`, `audit_mirror_errors_total`, `audit_mirror_dropped_total`, `audit_mirror_pending_total`, `audit_last_mirror_success` and per-sink detail. Shipping is best-effort by design, so this being alerted on is the only thing separating "durable audit" from "a local file that looks durable". A process-level sink registry backs it, because `AuditLogger` is built per request.
- `aetherya policy fingerprint [--json]` — emits both fingerprints for deployment pipelines to pin.

### Deployment readiness

- **Distributed rate limiting.** `RedisActorRateLimiter` shares the sliding window across processes via a sorted set per actor, with the drop/count/add/expire sequence in one pipeline so concurrent workers cannot read a stale count. The in-process limiter meant that behind `uvicorn --workers N` the effective limit was `N x requests_per_window` — the configured limit simply was not the limit that applied, and it scaled with replica count. Select via `rate_limit.backend: redis` (`AETHERYA_RATE_LIMIT_REDIS_URL`). **Fails closed**: an unreachable Redis refuses the request rather than silently going unlimited. A throttled request withdraws its own entry so a caller hammering the endpoint cannot extend its own window.
- **Policy version contract.** `AETHERYA_EXPECTED_POLICY_FINGERPRINT` (or `load_policy_config(..., expected_fingerprint=...)`) pins the policy a process may run; a mismatch raises `PolicyFingerprintMismatch` at load. Two replicas on different policies return different decisions for identical input and nothing surfaces that until someone diffs audit trails — pinning turns silent divergence into a startup failure. `/health` reports `policy_fingerprint_pinned` and `policy_fingerprint_match`.
- **Semantic layer readiness is now observable.** With `require_warm_semantic_model` the advisory layer declines to run on a cold model, which made it a silent no-op in any deployment that never warmed it. `/health` now reports `semantic_enabled`, `semantic_ready`, `semantic_model_warm` and `degraded`. The API server preloads the model before accepting traffic (`--no-warmup-semantic` to skip); `--require-semantic-ready` fails startup instead of serving degraded.
- **Audit durability and retention.** `AuditLogger` accepts `fsync=True` (off by default) and `mirrors=[...]`, an `AuditSink` fan-out for shipping each event to append-only storage (S3 object-lock, WORM log service). Mirrors receive the byte-identical line the primary wrote, so the chain verifies the same on either copy. Mirror failures increment `mirror_errors` rather than raising — a transient archive outage must not take the decision path down, but the counter must be monitored. The chain tip only advances after the authoritative write succeeds.

### Security

- **Adversarial sweep of the procedural corpus.** 26 systematic evasions were run against the new rules; 4 got through and are now closed, and 5 more were downgraded from `hard_deny` to `escalate` by quoting. Fixed: `r''m -rf /` (quote-split command name, previously **allowed outright**), `truncate -s 0 /dev/sda`, `echo x | tee /dev/sda`, and `python -c "shutil.rmtree('/')"`. The corpus is pinned as a regression fixture (`tests/fixtures/security_corpus/v1/procedural_evasions.json`) with per-case expectations; cases whose destructive intent is only resolvable at execution time (variable expansion, pipe contents, base64) are asserted to reach the confirmation band rather than hard-deny.
- **Quote and escape stripping moved into the shared normalizer.** Quoting is syntactic to a shell and inert in prose, but it splits any literal a pattern is anchored on. The same evasion worked against the **JailbreakGuard** (`ign''ore previous instructions` was undetected); both guards now normalize identically, which is the property `text_normalize` exists to guarantee. New procedural rules: `block_device_write_tool` (tee/truncate to a device), `interpreter_destruction` (`rmtree('/')`), `find_delete` (`find / -delete`).
- `Parser`: parameter and target values are no longer lowercased. Values were extracted from a lowercased copy of the input, so `param.path=/tmp/MyFile.TXT` was recorded and audited as `/tmp/myfile.txt` — a different file on any case-sensitive filesystem, meaning the audit trail did not describe the action that was authorised. Field *names* remain case-insensitive and tool names are still lowercased to match the execution allowlist.

### Added

- **Structured input as the preferred integration path.** `run_pipeline_structured(action, ...)` and `run_pipeline(..., action=...)` take a fully-formed `ActionRequest`, skipping the heuristic parser entirely so no part of the decision depends on inferring structure from free text. The HTTP API accepts an `action` object on `POST /v1/decide` alongside `raw_input`; the response reports `meta.input_mode`. Every other stage is unchanged: structured callers still pass the ABI contract and IntentEscalation, so declaring `intent="ask"` on a destructive payload bypasses nothing.
- `config.py`: `RateLimitBackendConfig` (loaded from `rate_limit`), `POLICY_FINGERPRINT_ENV`, `PolicyFingerprintMismatch`, `expected_policy_fingerprint()`.
- `rate_limiter.py`: `RateLimiter` protocol, `RedisActorRateLimiter`, `build_rate_limiter()`.
- `audit.py`: `AuditSink` protocol, `AuditLogger.fsync`, `AuditLogger.mirrors`, `AuditLogger.mirror_errors`.
- `api_server.py`: `warmup_semantic_layer()`, `--no-warmup-semantic`, `--require-semantic-ready`.

### Security (guard chain)

- **`ProceduralGuard` rewritten from substring matching to an anchored rule corpus.** The previous implementation tested `critical_tag.lower() in text`, which both missed real commands and fired on prose. Verified gaps that are now closed: `rm -fr /`, `rm -r -f /`, `rm --recursive --force /`, `rm -rf --no-preserve-root /` and extra-whitespace variants all degraded from `hard_deny` to `escalate`; `dd if=/dev/zero of=/dev/sda` was **allowed** outright, as were `> /dev/sda`, `shred`/`wipefs` on a device, and `mkfs.ext4 /dev/sda1`. Root-recursive-delete detection now parses `rm` invocations (flag clustering in any order, long flags, `--no-preserve-root`) and classifies the target against a set of root-like system paths. Matching runs over the shared security normalizer, so invisible-character obfuscation cannot split a command token.
- `ProceduralGuard`: severity tiering. `critical_tag_detected` is a hard-deny tag and is now reserved for irreversible destruction. `rm -rf` on a non-root path (`recursive_force_delete`, risk 55) and `curl|wget` piped into a shell (`remote_code_execution`, risk 70) land in the confirmation band instead of being hard-denied or ignored.
- `ProceduralGuard`: false positives removed. `explain what mkfs does` previously scored 100 via bare substring match; `mkfs` now requires a `/dev/` argument and `rm` rules require a path-like target, so `What does rm -rf do?` no longer fires.
- `ProceduralGuard`: all matching rules are collected. Score, confidence and reason come from the highest-severity match; the tag list is the de-duplicated union across every match, mirroring the JailbreakGuard contract.
- **New `intent_escalation` pipeline stage — the guard chain no longer depends on the parser's verb list.** `ExecutionGate` and `CapabilityGate` only evaluate `intent=operate`, so an executable command using a verb the parser did not know (`dd if=/dev/zero of=/dev/sda`) was classified `ask`, skipped both gates and reached `allow`. The stage re-derives operative intent from raw input using command shape — command substitution, pipes into a shell, redirects to absolute paths, known binaries carrying flags, device operands, `sudo` prefixes — plus any `ProceduralGuard` hit. The transform is monotone (`ask` → `operate` only), so it cannot be used to relax a request. Escalations are recorded in the audit context under `intent_escalation`.
- **`ActorRateLimiter` state is now bounded.** Windows were held in a plain dict keyed by actor and never released, so rotating the actor field grew the map without limit (measured: 50 000 distinct actors retained 50 000 deques indefinitely). Windows now live in an LRU map capped at `max_actors` (default 10 000) with fully-expired entries swept every `sweep_every` checks (default 1 000). LRU order is a security property, not just a memory one: an actor being actively rate-limited is by definition recently used, so flooding cannot evict — and thereby reset — the window of the actor it is trying to displace.

### Fixed

- `Parser`: meta-questions about a command no longer escalate. v0.8.0 classified any mention of an operative verb as operative, so `"What does rm -rf do?"` became an operative request with no declared tool — which scores 55 at the ExecutionGate, above the operative `confirm_at` of 50, and therefore always returned `escalate`. A narrow frame (`what does/is/are …`, `how does … work`, `explain/describe/define …`, anchored at the start, third person only) now keeps such inputs consultive. It is disqualified by any clause separator (`;`, `&&`, `|`, newline, `and then`, `then`), by an explicit `tool:` or `mode:operative`, and does not match first-person how-to phrasing, so `"How do I run a Docker container?"` and `"Can you delete all logs?"` are unchanged. This is an ergonomics fix, not a security boundary: `ProceduralGuard` matches the raw input regardless of intent and `IntentEscalation` raises the request back to `operate`, so `"explain rm -rf /"` is still hard-denied.
- `scripts/pre_api_gate.py`: the `shadow_timeout` scenario compared absolute subprocess wall time against fixed budgets, which measured interpreter startup and package imports rather than what the scenario asserts — that the shadow adds bounded latency and that `--no-wait-shadow` adds none. On a host where importing `aetherya.cli` alone costs 130 ms, the 150 ms `--no-wait-shadow` budget could not be met regardless of engine behaviour. Budgets now apply to the overhead over a shadow-disabled baseline invocation, and the wait path additionally excludes the measured provider-SDK import cost. The gate is hardware-independent as a result: measured overhead is 26 ms (no-wait) and 291 ms (wait, against a configured 100 ms shadow timeout), versus 157 ms and 733 ms of absolute wall time.

### Changed

- **The semantic constitution layer is now non-authoritative.** It is the only component in the decision path whose output depends on a learned model, so it can no longer decide alone: its risk contribution is capped at the new `constitution.semantic_max_risk` (default 60) and it emits only the non-hard-deny tag `semantic_advisory`. The cap is validated at policy load to sit strictly below every mode's `deny_at` — a policy that would grant the model authority to deny is rejected rather than silently accepted. Net effect: swapping the model can change whether a human is asked, never whether an action is refused outright.
- **The semantic layer never blocks a decision on a cold model load.** Loading `all-MiniLM-L6-v2` costs ~5 s in a fresh process; with `use_semantic` on by default this landed inside the decision path and made one-shot CLI use unusable (measured 5.6 s per `aetherya decide`, versus 0.15 s with the layer off). New `constitution.require_warm_semantic_model` (default `true`) makes the layer decline to run when the model is not already in the process cache, recording `constitution.semantic_skipped: model_not_warm` in the trace. Long-lived deployments call `aetherya warmup` at boot to make it available. CLI cold-start returns to ~0.16 s.
- **`FastKeywordEvaluator` ambiguity is decided by evidence, not text length.** Ambiguity was gated on `token_count < 10`, so inputs longer than ten tokens never reached the semantic layer — precisely where a paraphrased attack has the most room to hide. An input with no keyword evidence either way is now ambiguous regardless of length; length only modulates the confidence the fast layer reports in its own "clean" verdict. A keyword found only in negated form remains a definitive allow.
- `config/policy.yaml`: `procedural_guard.critical_tags` entries now activate rule families rather than literal substrings. The three shipped literals are unchanged in meaning; three symbolic families are added (`block_device_write`, `recursive_force_delete`, `remote_code_execution`). Unrecognised entries degrade to literal substring matching, so custom operator rules keep working.

### Added

- `text_normalize.py` — `normalize_security_text()`, extracted from `jailbreak.py` and now shared with `ProceduralGuard`, so both guards match against one canonical form and a bypass fixed in one is fixed in the other.
- `intent_escalation.py` — `IntentEscalator`, `IntentEscalationOutcome`, `apply_escalation()`.
- `config.py`: `IntentEscalationConfig` (`enabled`, `use_procedural_signal`, `use_shape_signals`), loaded from `policy.yaml` under `intent_escalation`.
- `config.py`: `ConstitutionConfig.semantic_max_risk` and `ConstitutionConfig.require_warm_semantic_model`, plus `_validate_semantic_authority()` enforcing the cap against every mode's `deny_at` at load time.
- `constitution.py`: `DEFAULT_SEMANTIC_MAX_RISK`, `SEMANTIC_ADVISORY_TAG`, `is_model_warm()`, and `SemanticEvaluator.can_evaluate()`.
- `rate_limiter.py`: `RateLimitConfig.max_actors`, `RateLimitConfig.sweep_every`, and `ActorRateLimiter.tracked_actors()` for observability.
- Audit trace: `context.intent_escalation` when a request was escalated; `context.constitution.semantic_model` naming the model behind an advisory signal; `context.constitution.semantic_skipped` distinguishing "the advisory layer declined to run" from "it found nothing".

- `audit_divergence.py` — ethical divergence telemetry over the audit trail. New command `aetherya audit divergence` (also `python -m aetherya.audit_divergence`) aggregates LLM-shadow results: shadow evaluation count, shadow errors, state mismatch rate, mean/max `risk_delta`, parse success rate, flag frequency, and top-N events by absolute risk delta (`--top`, `--min-abs-delta`, `--json`).
- Pipeline: the audited `llm_shadow` block now includes an `evaluation` sub-block (`parse_success`, `reasoning`, `flags`) when the provider performs a structured ethical evaluation. Dry-run shadow events are unchanged.
- `aetherya warmup` — preloads the semantic constitution model (`all-MiniLM-L6-v2` by default, `--model-name` to override) into the process cache and runs one dummy encode. Intended for deployment startup: with `use_semantic` enabled by default, the first ambiguous input would otherwise trigger the model download/load inside the decision path. Exposed as `warmup_semantic_model()` in `constitution.py`.
- `constitution.py`: `DEFAULT_SEMANTIC_MODEL` constant (`all-MiniLM-L6-v2`) replaces the inline model-name literal.
- `AnthropicLLMProvider` — Claude as LLM-shadow evaluator. Set `llm_shadow.provider: anthropic` with a Claude model (e.g. `claude-opus-4-8`); requires `ANTHROPIC_API_KEY` and the `anthropic` extra (`pip install -e ".[anthropic]"`). Same structured ethical evaluation and parse-fallback contract as the OpenAI provider. Sampling parameters are not forwarded (current Claude models reject them); a safety refusal (`stop_reason: refusal`) degrades to the neutral fallback score with `llm_parse_error` recorded. System prompt goes in the Messages API `system` field.
- `pyproject.toml`: new optional dependency group `anthropic` (`anthropic>=0.40.0`).

### Fixed

- CI: `test_chaos_byte_mutator_detects_chain_break_under_10ms` flaked on fresh runners — the single-shot latency measurement ran cold as the first test of the isolated `chaos_tests` job and exceeded the 10ms SLO (~12ms). The verification path is now warmed up before the timed window, mirroring the existing `semantic_slo` warmup pattern. Steady-state latency percentiles remain enforced by `chaos_benchmark`.
- CI: on `chaos_tests` failure, the pytest output is now published to the job summary (readable without authentication).

## v0.9.0 - 2026-07-04

### Added

- `Constitution`: semantic evaluation layer is now enabled by default (`use_semantic=True`). Configurable via new `constitution.use_semantic` flag in `policy.yaml` (set to `false` to run FastKeywordEvaluator only).
- `Constitution`: module-level model cache in `_default_model_factory` — the SentenceTransformer instance is loaded once per model name and shared across all `SemanticEvaluator` instances in the process.
- `FastKeywordEvaluator`: graduated confidence based on match evidence — `0.9` when a matched keyword appears in the principle name, `0.85` when two or more keywords match, `0.7` for a single keyword match. All matches are collected before deciding (previously stopped at first match).
- `FastKeywordEvaluator`: a keyword found only in negated form (e.g. "how to prevent delete accidents") now returns a definitive allow with `confidence=0.9`, skipping semantic escalation.
- `SemanticEvaluator`: new `semantic_score` field in evaluation results (cosine similarity of best-matching principle). Propagated by the pipeline to the audit trace as `context.constitution.semantic_score` when present.
- LLM shadow: `OpenAILLMProvider` now performs a real ethical evaluation instead of hash-derived telemetry. Sends a structured system prompt requesting JSON (`risk_score` 0–100, `reasoning`, `flags` from a fixed vocabulary) with pipeline context (mode, decision state, reason, core risk score). Response parsing strips markdown fences and falls back to a neutral score of 50 on any parse failure (`llm_parse_error` recorded in metadata). Metadata enriched with `llm_reasoning`, `llm_flags`, `llm_parse_success`.
- Pipeline: `core_risk_score` added to the LLM shadow request metadata so the shadow evaluator can compare against the deterministic decision.

### Changed

- `Constitution.__init__`: `use_semantic` default changed from `False` to `True`. Callers that need keyword-only evaluation must pass `use_semantic=False` explicitly or set `constitution.use_semantic: false` in policy.
- LLM shadow `suggested_risk_score` is no longer derived from a hash of the response text; it is the model-reported `risk_score` (or 50 on parse failure). `ethical_divergence.risk_delta` is now meaningful.

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
