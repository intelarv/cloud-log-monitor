---
name: Agent/LLM harness invariants
description: Non-obvious rules the chat-agent loop must uphold — degradation, DI testability, and DoS guards.
---

# Agent/LLM harness invariants

The chat-agent loop (`runAgentLoop` in `artifacts/api-server/src/lib/chat-agent.ts`)
is the prompt-injection + DoS surface for the whole product. These rules are not
obvious from a casual read of the code:

- **Never surface a raw `tool_call` JSON envelope to the user.** Any path that
  would otherwise "fall through" with the model's tool-call text (tool budget
  exhausted, etc.) MUST degrade to `deterministicAnswer(findings)` instead. The
  user-facing string is either a real prose answer or the deterministic redacted
  summary — never the internal protocol envelope, never an error page.
  **Why:** threat model §DoS + §Information Disclosure — error pages leak stack
  traces and raw envelopes confuse/expose internal scaffolding.

- **Every degradation path sets `degraded=true` + a `degrade_reason`** and these
  get ledgered on `chat.agent_turn`. Honest accounting depends on it.

- **The per-turn output-token cost cap must be checked for EVERY LLM response
  shape, before the tool-vs-final-answer split** — not only when the model wants
  another tool. A plain final answer that already blew the cap must degrade too.
  **Why:** a previous revision only checked the cap inside the `if (call)` branch,
  so an over-budget non-tool answer slipped through with `degraded=false`. There
  is a regression test pinning the non-tool-over-cap case.

- **The loop is dependency-injected** (`{runtime, callTool, limits}`) so it is
  unit-tested fully offline with fake runtimes/tools — no DB, no network. Keep it
  that way: retrieval (`retrieveCandidates`) stays in `runChatTurn`, the loop
  stays pure.

- **Bounded retry is best-effort cancel, NOT guaranteed no-double-charge.** On
  LLM timeout we call `iterator.return?.()` but do not await provider-side
  cancellation. Total cost is still bounded (max tool rounds × per-call timeout),
  but a strict no-double-charge guarantee would need real `AbortSignal` wiring in
  the runtime adapters — deliberately deferred.
