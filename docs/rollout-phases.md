# Rollout Phases

How to put ÆTHERYA in front of a real agent without betting the deployment on
a policy nobody has measured yet.

The engine always computes a full decision. A phase only decides **how much of
that decision is enforced**. Nothing about the policy, the integration or the
audit trail changes between phases — only the enforcement posture. That is what
makes it safe to start in observation mode and tighten later.

The phase is configuration, not code:

```yaml
# config/policy.yaml
enforcement:
  phase: 1        # 1 shadow · 2 hard_deny · 3 full
```

Two ways to see it:

```bash
python examples/agent_loop.py --phase 1     # engine in-process
python examples/sidecar_agent.py --phase 1  # agent talking to the container
```

And one way to know when to advance:

```bash
aetherya rollout report --phase 1 --audit-path audit/decisions.jsonl
```

That command evaluates the exit criteria below against the audit trail, prints
the `hard_deny` events that need human review, and exits non-zero until the
phase is ready — usable as a gate in a promotion pipeline.

| Phase | Blocks | Confirms | Risk of deploying it |
|---|---|---|---|
| 1 — shadow | nothing | nothing | none: behaviour is unchanged |
| 2 — hard-deny | `hard_deny` | nothing | refuses only deterministic tag hits |
| 3 — full | `hard_deny`, `deny` | `escalate` | introduces human latency |

---

## Phase 1 — Shadow

**Posture.** Every proposed action is sent to the engine and every decision is
recorded. Then the action executes regardless. The agent's behaviour is
byte-for-byte what it was before.

**Why start here.** You do not know your false-positive rate. No synthetic
corpus can tell you, because the distribution that matters is your agents, your
tools, your paths. Two weeks of real traffic will.

**Wiring.** Call the engine, log the decision, ignore it:

```python
decision = run_pipeline_structured(action, constitution, actor, cfg)
audit.log(actor=actor, action=action.raw_input, decision=decision.to_dict(), context={})
result = execute(tool, args)          # unconditional
```

**What to measure.** From the audit trail, per state:

| Metric | Why |
|---|---|
| `hard_deny` count and rate | the volume phase 2 will start refusing |
| `hard_deny` events, **read individually** | the only way to know they are true positives |
| `deny` + `escalate` rate | the confirmation load phase 3 would impose |
| distinct actors and tools hitting each state | tells you whether it is one broken caller or systemic |
| `intent_escalation` block frequency | how often the parser needed correcting |
| `constitution.semantic_skipped` | whether the advisory layer is running at all |

`aetherya audit divergence` aggregates the shadow telemetry; the audit JSONL is
the source for the rest.

**Exit criteria — all of them:**

1. At least 2 weeks, or 10 000 decisions, whichever is later.
2. **Every** `hard_deny` event reviewed by a human and confirmed a true positive.
   Not a sample — every one. There will not be many; that is the point of the
   tier.
3. Zero `hard_deny` on a code path a human agrees should have been allowed.
4. The audit chain verifies clean (`--require-chain`) over the whole window.

**Recording the review.** Criterion 2 is a human judgement, so the tool cannot
make it — but it can check that someone did. Open the operator console, work
through the hard-deny queue, and mark each event:

```bash
export AETHERYA_CONSOLE_API_KEY=...   # required: the verdict is attributed
make api_serve                        # console at http://127.0.0.1:8080/
```

Each verdict is appended to `audit/reviews.jsonl` against the audit `event_id`,
with the reviewer's name and timestamp. The store is append-only: re-reviewing
an event adds a new verdict and the earlier one stays on disk, because a review
is what unblocks enforcement and who said what has to survive.

`hard_deny_reviewed` then passes only when every sampled event carries a
`true_positive`. Two things deliberately do *not* pass it:

- **Any `false_positive`.** Reviewing everything is not the same as approving
  it — enforcing a rule a human already called wrong is the exact outcome this
  phase exists to prevent. Fix the rule, then restart the window.
- **Events beyond `max_hard_deny_samples`.** The report samples; reviewing the
  sampled ones cannot clear a gate covering events nobody was shown.

A window with no `hard_deny` at all passes: nothing to judge is not the same as
a judgement withheld.

**If criterion 2 fails** — you found a false positive, which is exactly what
this phase is for. In order of preference:

1. Add the case to `tests/fixtures/security_corpus/v1/procedural_evasions.json`
   with the expectation you actually want, and fix the rule. A false positive is
   a detection bug, not a reason to loosen the policy globally.
2. If the action is genuinely legitimate and genuinely looks destructive, narrow
   the rule family in `procedural_guard.critical_tags` rather than removing it.
3. Only as a last resort: move the offending family out of `critical_tags`,
   which demotes it from hard-deny to a scored signal.

Restart the clock on criterion 1 after any policy change — the fingerprint
changed, so you are measuring a different engine.

---

## Phase 2 — Hard-deny enforcement

**Posture.** Refuse `hard_deny`. Everything else executes and is logged.

**Why this subset first.** `hard_deny` comes from deterministic tags — an
irreversible destructive command, a jailbreak pattern, a tool that is not on the
allowlist, an actor without the capability. It does not depend on threshold
tuning, weights, or the learned layer. It is the highest-precision, lowest-volume
thing the engine produces, so it is where enforcement costs least and buys most.

`deny` is deliberately left unenforced here: it comes from a weighted score
crossing `deny_at`, and score tuning is exactly what you have not validated yet.

**Wiring.** One line changes:

```python
decision = run_pipeline_structured(action, constitution, actor, cfg)
if decision.state == "hard_deny":
    return f"REFUSED BY POLICY: {decision.reason}"   # goes back to the model
result = execute(tool, args)
```

**The refusal must go back to the model as tool output.** A well-behaved agent
replans; a compromised one cannot retry its way past it. Do not raise an
exception that kills the run — you lose the trajectory that would tell you what
the agent tried next.

**What to measure.**

| Metric | Alert when |
|---|---|
| refusals per day | a sudden jump means either an attack or a policy regression |
| agent task success rate | compare against the phase 1 baseline; a drop is your real cost |
| repeated refusals for the same actor+tool | a caller stuck in a loop against the boundary |
| `deny` and `escalate` volume | still shadow — this is your phase 3 forecast |

**Exit criteria:**

1. 2+ weeks with enforcement on and no incident caused by a refusal.
2. Agent task success rate within noise of the phase 1 baseline.
3. The `escalate` volume you measured is one a human can actually service.
   If phase 1 showed 400 escalations/day and you have one on-call approver,
   phase 3 will fail — fix the policy or the staffing before you get there,
   not after.

---

## Phase 3 — Full enforcement

**Posture.** Refuse `hard_deny` and `deny`. Hold `escalate` for human
confirmation via a signed approval proof.

**Why last.** This is where the engine delivers its actual value — a human in
the loop before an irreversible action — and it is also the only phase that
introduces latency and friction for users. You want the false-positive rate and
the escalation volume both known before you impose that.

**Wiring.** The held action needs an out-of-band approval round trip:

```python
decision = run_pipeline_structured(action, constitution, actor, cfg)

if decision.state in {"hard_deny", "deny"}:
    return f"REFUSED BY POLICY: {decision.reason}"

if decision.state == "escalate":
    proof = request_human_approval(action)          # your approval channel
    if proof is None:
        return "HELD: awaiting human approval"
    action = replace(action, parameters={**action.parameters, "confirm_proof": proof})
    decision = run_pipeline_structured(action, constitution, actor, cfg)
    if decision.state != "allow":
        return f"REFUSED BY POLICY: {decision.reason}"

result = execute(tool, args)
```

The proof is minted by the approvals service (`aetherya confirmation sign`,
localhost-only, admin key) and is single-use by default — see
[security-model.md](security-model.md#confirmation-and-approval-flow).

**What to measure.**

| Metric | Alert when |
|---|---|
| time-to-approval, p50 and p95 | approvals are the new latency floor |
| abandonment rate | held actions nobody ever answers — the policy is too noisy |
| approval rate | approving ~100% means the threshold is too low to be informative |
| replay rejections | should be ~0; a nonzero rate means a client is retrying proofs |

**If the approval rate is near 100%**, the escalation is not carrying
information: either raise `confirm_at` for that mode or narrow the rule that
produces it. An approval step every human always clicks through is worse than
no approval step, because it trains people to click through.

---

## Operating configuration

Target state once phase 3 is stable:

```yaml
# config/policy.yaml
modes:
  operative:
    thresholds: { deny_at: 80, confirm_at: 50, log_only_at: 0 }

rate_limit:
  backend: redis          # mandatory: memory means N workers = N x the limit

confirmation:
  enabled: true
  evidence:
    signed_proof:
      enabled: true
      replay_store: redis
      replay_mode: single_use

constitution:
  use_semantic: true
  require_warm_semantic_model: true
```

```bash
export AETHERYA_EXPECTED_POLICY_FINGERPRINT="$(aetherya policy fingerprint --json \
  | python -c 'import sys,json; print(json.load(sys.stdin)["effective_fingerprint"])')"
export AETHERYA_CONFIRMATION_HMAC_KEY=...
export AETHERYA_RATE_LIMIT_REDIS_URL=redis://...
export AETHERYA_CONFIRMATION_REPLAY_REDIS_URL=redis://...
export AETHERYA_ATTESTATION_KEY=...
```

Run the approvals service separately, on localhost, behind an admin key. Run
`aetherya warmup` at boot so the advisory layer participates. Attach a durable
audit mirror and alert on `audit_mirror_ok` going false.

**Readiness gate.** A replica should not receive traffic unless `/health`
reports:

```
ok: true
policy_fingerprint_match: true
degraded: false
audit_mirror_ok: true
```

---

## What this plan does not cover

- **Approval channel.** Slack, PagerDuty, a web form — out of scope for the
  engine. It mints and verifies proofs; delivering them to a human is yours.
- **Per-tenant policy.** One fingerprint per process today. Multi-tenant means
  either a process per policy or a change to the loading model.
- **Executor isolation.** ÆTHERYA decides; it does not sandbox. A decision
  boundary and an execution sandbox are complementary, not substitutes.
