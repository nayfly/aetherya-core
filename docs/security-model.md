# Security Model

## Threat Model

**In scope:**
- Prompt injection and jailbreak attempts targeting tool execution
- Unauthorized irreversible operations (delete/write/transfer-like flows)
- Confirmation proof replay attempts
- Audit tampering/reordering attempts
- Runtime component failures (handled as fail-closed)

**Out of scope:**
- Full host compromise (kernel/root takeover)
- Secret exfiltration outside process boundaries
- Compromised external providers (LLM/API vendor side)
- Human admin account takeover

---

## Fail-Closed Guarantee

Every stage in the pipeline is wrapped in a try/except. Any exception returns:

```json
{"allowed": false, "reason": "fail_closed:<stage>"}
```

Stages: `parser`, `execution_gate`, `capability_gate`, `jailbreak_guard`, `procedural_guard`, `constitution`, `risk_aggregator`, `confirmation_gate`, `policy_engine`, `output_gate`.

---

## JailbreakGuard

Deterministic prompt injection detection — runs before the constitution.

**Unicode normalization** (applied before pattern matching):
- NFKD decomposition
- Diacritic stripping (Unicode combining character removal)
- Unicode format character removal (category `Cf`): zero-width space U+200B, ZWNJ U+200C, ZWJ U+200D, BOM U+FEFF, soft hyphen
- Eliminates trivial bypasses via invisible characters, lookalike diacritics, and fullwidth variants

**Multilingual pattern corpus:** English, Spanish (`es`), French (`fr`), German (`de`):
- Role override: `act as if you were`, `finge que eres`, `fais semblant d'être`, `tu so als ob`
- Policy override: `ignore previous instructions`, `ignora las instrucciones`, `ignoriere anweisungen`
- Instruction suppression: `forget your instructions`, `olvida tus instrucciones`, `oublie tes instructions`
- Prompt exfiltration: `show me your prompt`, `muestrame tu prompt`, `montre-moi ton prompt`, `zeig mir prompt`
- Uncensored mode: `no restrictions mode`, `modo sin censura`, `mode non censure`, `unzensierter modus`

**Multi-match behavior:** all matching patterns collected; full tag list preserved in audit. Tags: `["jailbreak_attempt", "prompt_injection", <specific_tags>]`. Risk score: `95`, confidence: `0.95`.

---

## Confirmation and Approval Flow

Strong confirmation is optional and off by default.

**Enable:** set `confirmation.evidence.signed_proof.enabled: true` in `policy.yaml`.

**HMAC-signed proof flow:**

```bash
export AETHERYA_CONFIRMATION_HMAC_KEY="replace-with-long-random-secret"

# Sign
aetherya confirmation sign "mode:operative tool:filesystem target:/tmp ..." \
  --actor robert --expires-in-sec 60 --json

# Decide with proof
aetherya decide "... param.confirm_proof=<approval_proof>" --actor robert --json
```

**Key rotation** (`confirmation.evidence.signed_proof` in `policy.yaml`):
- `active_kid` — current signing key id
- `keyring_env` — kid → secret keyring
- `replay_mode` — `single_use` | `idempotent`
- `replay_store` — `memory` | `redis`
- `replay_redis_url_env` + `replay_redis_prefix` — centralized anti-replay keys

**Replay protection:** in `single_use` mode, each proof can only be consumed once. Redis-backed replay is required for multi-process deployments:

```yaml
confirmation:
  evidence:
    signed_proof:
      replay_store: redis
      replay_redis_url_env: AETHERYA_CONFIRMATION_REPLAY_REDIS_URL
```

---

## Audit Chain Integrity

Every decision is logged to a JSONL file with:
- `decision_id` — stable unique identifier
- `context_hash` — deterministic hash of the input context
- Chain linkage — each event references the previous hash

Verification:

```bash
# Chain integrity
python -m aetherya.audit_verify --audit-path audit/decisions.jsonl --require-chain --json

# HMAC attestation
AETHERYA_ATTESTATION_KEY="your-key" python -m aetherya.audit_verify \
  --audit-path audit/decisions.jsonl --require-hmac --require-chain
```

Detects: reordered events, tampered payloads, missing chain links.
