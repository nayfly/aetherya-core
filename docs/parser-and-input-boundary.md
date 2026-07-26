# Parser and Input Boundary

## Role

The parser converts raw text input into a typed `ActionRequest`. It is the first stage of the pipeline and the boundary where input authority is established.

The parser is **non-authoritative for security mode by design**: structured callers that explicitly pass `mode:operative tool:...` fields always take precedence over any heuristic.

---

## Security Contract

Operative-content signals take unconditional priority over question framing:

```
is_meta_question   = meta_frame AND no clause separator
                     AND no tool_match AND mode_hint != "operative"

has_operative_content = tool_match
                     OR mode_hint == "operative"
                     OR (operative_verb AND NOT is_meta_question)

if has_operative_content:
    → intent=operate / mode=operative

else:
    → intent=ask / mode=consultive   ← safe default, always
```

This means:
- `"Can you run rm -rf /tmp"` → `intent=operate / mode=operative` (contains operative verb `run`)
- `"Delete the config file"` → `intent=operate / mode=operative` (operative verb `delete`)
- `"What is the weather?"` → `intent=ask / mode=consultive` (no operative signals)
- `"What does rm -rf do?"` → `intent=ask / mode=consultive` (meta-question, see below)

The question heuristic **only applies** to inputs with no operative signals. It cannot downgrade the security mode of an operational request.

---

## Meta-Questions

A meta-question asks *about* a command rather than requesting one. Treating a
bare mention of an operative verb as an operation sent every such question to
`escalate`, because an operative request with no declared `tool:` scores 55 at
the ExecutionGate — above the operative `confirm_at` of 50.

**Frames** (anchored at the start of the input, third person only):
`what does/do/is/are …`, `how does … work`, `explain …`, `describe …`, `define …`

**Disqualifiers** — any of these and the frame does not apply:

| Disqualifier | Rationale | Example |
|---|---|---|
| Clause separator (`;`, `&&`, `\|`, newline, `and then`, `then`) | the input may chain an imperative after the frame | `explain; rm -rf /` |
| `tool:<name>` present | an explicit declaration always wins | `what does tool:shell param.command=whoami do` |
| `mode:operative` present | same | `what does mode:operative rm -rf do` |
| First-person how-to | a request for instructions, not a meta question | `How do I run a Docker container?` |

**This is an ergonomics fix, not a security boundary.** The frame can only relax
inputs that carry no command shape and no destructive content, because two
independent layers run afterwards on the raw input regardless of intent:

- `ProceduralGuard` matches destructive commands independently of classification
- `IntentEscalation` raises the request back to `operate` on any procedural hit
  or command-shape signal

So `"explain rm -rf /"` parses as `ask`, is escalated back to `operate`, and is
hard-denied. Verified in `tests/test_intent_escalation.py`
(`test_meta_question_frame_is_not_a_bypass`).

---

## Operative Signals

The parser recognizes these signals as operative content:

**Explicit tool prefix:** `tool:<name>` in the input string.

**Operative verb keywords** (case-insensitive):
`run`, `execute`, `delete`, `send`, `curl`, `docker`, `rm`, `write`, `create`, `drop`, `deploy`, `restart`, `kill`, `stop`, `start`, `install`, `uninstall`, `update`, `upgrade`, `transfer`, `move`, `copy`, `chmod`, `chown`

**Explicit mode hint:** `mode:operative` in the input string.

---

## Structured Input Format

Structured callers can pass explicit fields to bypass heuristic parsing entirely:

```
mode:operative tool:filesystem target:/tmp param.path=/tmp/a param.operation=write param.confirm_token=ack:abc12345
```

Fields:
- `mode:` — `operative` | `consultive`
- `tool:` — tool name (validated against allowlist in `execution_gate`)
- `target:` — target resource
- `param.<key>=<value>` — tool parameters
- `param.confirm_token=ack:<id>` — confirmation token
- `param.confirm_context=<value>` — confirmation context
- `param.confirm_proof=<hmac_proof>` — out-of-band signed proof (optional)

---

## Capability Gate Interaction

The `capability_gate` only evaluates requests where `action.intent == "operate"`. Requests classified as `ask/consultive` skip capability checks entirely. This makes correct parser classification critical for security: misclassifying an operative request as `ask` would bypass capability enforcement.
