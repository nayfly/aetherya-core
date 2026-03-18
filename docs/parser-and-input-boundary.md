# Parser and Input Boundary

## Role

The parser converts raw text input into a typed `ActionRequest`. It is the first stage of the pipeline and the boundary where input authority is established.

The parser is **non-authoritative for security mode by design**: structured callers that explicitly pass `mode:operative tool:...` fields always take precedence over any heuristic.

---

## Security Contract

Operative-content signals take unconditional priority over question framing:

```
has_operative_content = tool_match OR operative_verb OR mode_hint=="operative"

if has_operative_content:
    → intent=operate / mode=operative

else:
    → intent=ask / mode=consultive   ← safe default, always
```

This means:
- `"Can you run rm -rf /tmp"` → `intent=operate / mode=operative` (contains operative verb `run`)
- `"Delete the config file"` → `intent=operate / mode=operative` (operative verb `delete`)
- `"What is the weather?"` → `intent=ask / mode=consultive` (no operative signals)

The question heuristic **only applies** to inputs with no operative signals. It cannot downgrade the security mode of an operational request.

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
