# Putting ÆTHERYA in front of an agent you did not write

The sidecar in [rollout-phases.md](rollout-phases.md) requires editing the agent
loop. Most agent runtimes — OpenClaw, LiteLLM, LangChain, anything that accepts
a custom OpenAI-compatible provider — cannot be edited that way, or you do not
want to fork them.

The gateway solves it by changing what the agent talks to instead of what it
does. It speaks the OpenAI chat-completions protocol, so the runtime treats it
as just another provider:

```
OpenClaw ──► ÆTHERYA gateway ──► OpenAI | Anthropic
                  │
             every tool call the model proposes is ruled on
             before the agent ever sees it
```

The agent never learns there is a boundary. A tool call the policy refuses is
removed from the response and replaced with a line of text explaining why, so
the model can replan — and the audit trail records the decision either way.

---

## Run it

```bash
export ANTHROPIC_API_KEY=sk-ant-...
aetherya-gateway --provider anthropic --model claude-opus-5 --actor openclaw
```

or

```bash
export OPENAI_API_KEY=sk-...
aetherya-gateway --provider openai --model gpt-4o-mini --actor openclaw
```

It binds `127.0.0.1:8090` and prints its posture:

```
[gateway] anthropic/claude-opus-5 · phase 1 (shadow) · http://127.0.0.1:8090/v1
```

| Flag | Default | Notes |
|---|---|---|
| `--provider` | `anthropic` | `anthropic` or `openai` |
| `--model` | `claude-opus-5` | Passed upstream; a request may override it |
| `--actor` | `openclaw` | **Must exist in `capability_matrix.actors`** — see below |
| `--phase` | from `policy.yaml` | `1` shadow · `2` hard-deny · `3` full |
| `--audit-path` | `audit/decisions.jsonl` | Feeds the operator console |
| `--effort` | `high` | Anthropic only |

**The gateway holds your upstream API key and authenticates nobody.** Keep it on
loopback. Binding it elsewhere prints a warning; it is not a suggestion.

---

## Point OpenClaw at it

In `openclaw.json`:

```json5
{
  agents: {
    defaults: {
      model: { primary: "aetherya/claude-opus-5" }
    }
  },
  models: {
    providers: {
      aetherya: {
        baseUrl: "http://localhost:8090/v1",
        apiKey: "not-used",
        api: "openai-completions",
        timeoutSeconds: 300,
        models: [
          {
            id: "claude-opus-5",
            name: "Claude Opus 5 via ÆTHERYA",
            contextWindow: 200000,
            maxTokens: 8192
          }
        ]
      }
    }
  }
}
```

`apiKey` is deliberately junk: OpenClaw talks to the gateway, and the gateway
holds the real credential. That is a property worth keeping — the agent process
never sees your provider key.

Then `openclaw configure` (existing install) or `openclaw onboard` (fresh).

---

## Add your actor to the capability matrix

This is the one step that is easy to skip and expensive to skip:

```yaml
# config/policy.yaml
capability_matrix:
  actors:
    openclaw:
      roles: [operator]
      tools: []
      operations: []
```

An actor the matrix has never heard of is denied on **every** call. In phases 1
and 2 that is invisible, because `deny` is not enforced — so the
misconfiguration sits there silently until phase 3 turns your agent into a
brick. The gateway therefore refuses to start at phase 3 with an unknown actor,
and warns at phases 1 and 2.

Note that the tools your agent uses must also be in `execution_gate.allowed_tools`.
A tool that is not on the allowlist is a `hard_deny` — the tier phase 2 enforces.
Run in phase 1 first and read the audit trail; that is exactly what it is for.

---

## Check it before trusting it

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python scripts/gateway_smoke.py --provider anthropic --phase 2
```

This starts the gateway, points a real OpenAI SDK client at it, and asks a real
model to run `rm -rf /` with a `shell` tool available. It reports what the model
proposed, what the policy ruled, and what survived to the client. Exits non-zero
if a destructive call got through. Costs a few cents.

---

## What this costs you

**Streaming latency.** A verdict needs the whole tool call — you cannot rule on
half of one. So the upstream response is completed before anything reaches the
client. `stream: true` still returns SSE frames and clients keep working, but
the tokens arrive in a burst at the end rather than as they are generated. For a
tool-using agent this is usually invisible; for a chat UI it is not.

**A hop.** One extra process between the agent and the provider, holding your
key. Gate the port accordingly.

**Tool vocabulary mapping.** The gateway does not know your agent's tools, so it
maps them generically: tool name → `tool`, arguments → `parameters`, and a
readable rendering of the arguments → `raw_input` (which is what ProceduralGuard
and JailbreakGuard read, so a destructive command hidden inside an argument is
still seen). If your tools carry structure the policy should reason about
specifically, encode it in `execution_gate.allowed_parameters` rather than
relying on the generic mapping.

---

## What it does not do

- **It does not sandbox.** ÆTHERYA decides; execution isolation is a separate
  concern and a complementary one.
- **It does not gate model output text**, only proposed tool calls. Use
  `output_gate` for response content.
- **It does not handle phase-3 confirmations.** An `escalate` at phase 3 is
  refused like a `deny`, because there is no approval round trip in a single
  chat-completions call. Agents that need held-for-approval semantics want the
  sidecar in [rollout-phases.md](rollout-phases.md#phase-3--full-enforcement).
