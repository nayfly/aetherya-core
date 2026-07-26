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

Stages: `parser`, `intent_escalation`, `execution_gate`, `capability_gate`, `jailbreak_guard`, `procedural_guard`, `constitution`, `risk_aggregator`, `confirmation_gate`, `policy_engine`, `output_gate`.

---

## Intent Escalation

`ExecutionGate` and `CapabilityGate` only evaluate requests whose intent is
`operate`, which made the guard chain depend on the parser correctly recognising
a command. The escalation stage removes that coupling by re-deriving operative
intent from the raw input, independent of the parser's verb list.

**Signals** (any one escalates):

| Signal | Example |
|--------|---------|
| `procedural_command_detected` | any `ProceduralGuard` hit |
| `command_substitution` | `` echo $(whoami) ``, `` `id` `` |
| `pipe_to_shell` | `curl https://x \| sh` |
| `redirect_to_path` | `report > /etc/passwd` |
| `binary_with_arguments` | `systemctl --now disable nginx` |
| `device_operand` | `if=/dev/zero`, `of=/dev/sda` |
| `privilege_escalation` | `sudo reboot` |

**Monotonicity:** the stage only raises `ask`/`consultive` to
`operate`/`operative`. It can never relax a request, so it cannot itself be
used as a bypass. Escalations are recorded in the audit context under
`intent_escalation`. Disable via `intent_escalation.enabled: false`.

---

## ProceduralGuard

Detects irreversible or privileged system operations. Matching runs over the
same normalized form as the JailbreakGuard (see below), so invisible-character
and diacritic obfuscation cannot split a command token.

Rules are **governed by `policy.yaml`**: each entry in
`procedural_guard.critical_tags` activates a rule family. Legacy literals expand
to flag-order-tolerant, argument-anchored patterns; unrecognised entries degrade
to literal substring matching so custom operator rules keep working.

| Config key | Covers | Risk |
|-----------|--------|------|
| `rm -rf /` | root recursive delete — `-rf`, `-fr`, `-r -f`, `--recursive --force`, `--no-preserve-root`, and top-level system paths (`/etc`, `/usr`, `/var`, …) | 100 (hard-deny) |
| `mkfs` | filesystem format — **requires a `/dev/` argument** | 100 (hard-deny) |
| `:(){:\|:&};:` | fork bomb, tolerant to spacing | 100 (hard-deny) |
| `block_device_write` | `dd of=/dev/sdX`, `> /dev/sdX`, `shred`/`wipefs`/`tee`/`truncate` on a device | 100 (hard-deny) |
| `interpreter_destruction` | `shutil.rmtree('/')` inside an interpreter one-liner | 100 (hard-deny) |
| `find_delete` | `find / … -delete` | 100 (hard-deny) |
| `recursive_force_delete` | `rm -rf` on a **non-root** path | 55 (confirm) |
| `remote_code_execution` | `curl`/`wget` piped into a shell | 70 |

**Severity tiering matters.** `critical_tag_detected` is a hard-deny tag, so it
is reserved for irreversible destruction. `rm -rf /tmp/build` is dangerous but
recoverable: hard-denying it would make the engine unusable, so it lands in the
confirmation band instead.

**Discussion is not execution.** Rules are anchored on command arguments, so
`explain what mkfs does` and `What does rm -rf do?` do not fire — the first has
no device argument, the second no path target.

### Evasion coverage

The corpus is exercised by a pinned regression fixture,
`tests/fixtures/security_corpus/v1/procedural_evasions.json` (26 cases). All are
refused; the split reflects what is knowable from the text alone.

**Hard-denied** — destructive intent unambiguous: shell quoting and escapes
(`r''m -rf /`, `rm -rf '/'`, `/et\c`), whitespace variants (tabs, repeated
spaces, embedded newlines), command prefixes (`env`, `sudo sh -c`), block-device
writes, interpreter one-liners, `find / -delete`.

**Escalated to confirmation** — the target only resolves at execution time, so
the text cannot justify a hard deny: variable expansion (`$CMD -rf /`,
`rm -rf $P`), command substitution, base64-then-`sh`, `cd / && rm -rf .`,
`ls / | xargs rm -rf`.

**Known limits.** Detection is textual. Arbitrary computed indirection — a
destructive command assembled at runtime from data the engine never sees —
cannot be resolved statically and is out of scope; that is what the confirmation
band and the capability matrix are for.

**Multi-match behavior:** all matching rules are collected. Score, confidence
and reason come from the highest-severity match; the tag list is the de-duplicated
union across every match.

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

---

## Deployment Contracts

Properties the engine cannot enforce from inside a single process, and how they
are surfaced.

### Rate limiting across replicas

`rate_limit.backend: memory` keeps windows in process memory. Behind N workers
the effective limit is `N x requests_per_window` — the configured limit is not
the limit that applies. Any multi-worker or multi-replica deployment must set
`backend: redis`.

```yaml
rate_limit:
  backend: redis
  requests_per_window: 60
  window_seconds: 60.0
  redis_url_env: AETHERYA_RATE_LIMIT_REDIS_URL
```

The Redis backend **fails closed**: if Redis is unreachable, `check()` returns
False and the pipeline records `fail_closed:rate_limit`. A limiter that fails
open is not a limiter.

### Policy version pinning

Two replicas running different policies return different decisions for identical
input, and nothing surfaces that until someone diffs audit trails. Pin the
fingerprint each process is allowed to load:

```bash
export AETHERYA_EXPECTED_POLICY_FINGERPRINT="$(aetherya policy fingerprint --json \
  | python -c 'import sys,json; print(json.load(sys.stdin)["effective_fingerprint"])')"
```

Two fingerprints are recorded, and the pin uses the second:

| Field | Hashes | Answers |
|---|---|---|
| `policy_fingerprint` | the file's exact bytes | which file did this replica load |
| `effective_fingerprint` | the loaded config, defaults resolved | would it decide the same way |

Hashing file bytes is wrong in both directions. Reformatting the YAML or editing
a comment changes it without changing behaviour, and — the case that matters — a
code upgrade that changes a *default* leaves the file untouched, so the byte hash
is unchanged while the engine decides differently. Only the effective fingerprint
sees that.

A mismatch raises `PolicyFingerprintMismatch` at load, so the replica refuses to
start rather than deciding under an unintended policy. `/health` reports
`policy_fingerprint`, `policy_fingerprint_pinned` and `policy_fingerprint_match`.

### Semantic layer readiness

The advisory layer declines to run on a cold model (see *Determinism and the
semantic layer* in the architecture doc), which makes it a silent no-op in any
deployment that never warms it. `/health` exposes the actual state:

| Field | Meaning |
|---|---|
| `semantic_enabled` | the policy asks for the layer |
| `semantic_model_warm` | the model is in the process cache |
| `semantic_ready` | the layer will actually participate in decisions |
| `degraded` | enabled but not ready — decisions run keyword-only |

The API server warms the model before accepting traffic. Use
`--require-semantic-ready` to fail startup instead of serving degraded.

### Audit retention

A local JSONL file does not survive an ephemeral container and offers no
retention. Two independent knobs:

- `AuditLogger(..., fsync=True)` — forces each event to disk before returning.
  Costs a syscall per decision; without it a hard kill can leave the on-disk
  chain shorter than what the process believed it wrote.
- `AuditLogger(..., mirrors=[sink])` — fans each event out to append-only
  storage. The mirror receives the byte-identical line the primary wrote, so
  chain verification produces the same result on either copy.

Mirror failures increment `mirror_errors` instead of raising, so an archive
outage does not take the decision path down. **Monitor that counter** — a mirror
that fails silently is worse than no mirror. `/health` exposes it:

| Field | Meaning |
|---|---|
| `audit_mirror_configured` | any sink is registered |
| `audit_mirror_ok` | every sink has delivered and not since failed |
| `audit_mirror_errors_total` | failed deliveries |
| `audit_mirror_dropped_total` | events abandoned after retries or queue overflow |
| `audit_mirror_pending_total` | queued but not yet shipped |
| `audit_last_mirror_success` | epoch seconds of the last successful delivery |

Shipped implementations: `HTTPAuditSink` (batched, bounded queue, retry — point
it at Loki, Vector, Splunk HEC or an S3-fronting collector) and `FileAuditSink`
(second path, e.g. a mounted volume an archival agent tails). WORM and retention
are properties of the destination, not of the sink.

Chain verification is job-friendly: `python -m aetherya.audit_verify
--audit-path <path> --require-chain --json` exits `0` (valid), `1` (tampering
detected) or `2` (unreadable), suitable for a cron or Kubernetes Job.
