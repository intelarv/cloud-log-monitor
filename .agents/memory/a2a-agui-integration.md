---
name: A2A + AG-UI protocol integration
description: How the official agent↔agent (@a2a-js/sdk) and UI↔agent (@ag-ui/*) protocols are wired in api-server, plus the non-obvious SDK gotchas and the security boundary rules.
---

# A2A + AG-UI protocol seams

The Supervisor talks to the Triage/Verifier agents over the **official A2A
protocol** (`@a2a-js/sdk`), and the dashboard chat consumes **official AG-UI
events** (`@ag-ui/encoder` / `@ag-ui/core`). Both replaced hand-rolled paths.
Code lives in `artifacts/api-server/src/lib/a2a/` and `lib/sse.ts`.

## SDK gotchas (cost real debugging time)

- **`@a2a-js/sdk/server/express` `agentCardHandler()` and `jsonRpcHandler()` are
  express `Router`s that handle `"/"` internally.** Mount them with
  `app.use(path, mw, handler)`, NOT `app.get`/`app.post(fullPath, ...)` — the
  latter 404s because the router never matches the sub-path.
  **Why:** they call `router.get("/")` / `router.post("/")` inside; the mount
  path is the prefix.
- **`message/send` may return either a `Message` or a `Task`** for the same
  executor, non-deterministically (timing-dependent). A spec-compliant client
  MUST handle both. For a `Task`, dig the data part out of
  `status.message.parts`, then `artifacts[].parts`, then the last `agent`
  `history` message. See `client.ts:extractResponseData`.
  **Why:** the `DefaultRequestHandler` decides shape based on event ordering; you
  cannot rely on always getting a `Message`.

## Security boundary rules (do not regress)

- **Executors must forward the PARSED (Zod-stripped) finding, never the raw
  inbound object.** `findingShapeSchema` lists exactly the fields the agents read
  (id, classification, subclass, severity, source, detectorVersion,
  redactedEvidence). Zod's default object parse drops unknown keys, so
  `rawEvidence`/`rawEvidenceRef` cannot cross the wire even if a caller smuggles
  them. Do **not** revert to `(part.data as {finding}).finding as FindingSafe`.
  **Why:** a raw cast makes the redacted-only boundary an *assumption*; parse+strip
  makes it *enforced*. Covered by the "strips rawEvidence" test in `a2a.test.ts`.
- Returned agent rationale is re-scanned by `scanForPhi` **before** the ledger
  write (in `supervisor.ts`) — same as the old in-process path. Keep it.
- A2A routes are **loopback-only**: deliberately NOT in the artifact's proxy
  `paths` (only `/api` is). Shared-secret bearer auth (`a2aAuthMiddleware`,
  `timingSafeEqual`) gates both card + JSON-RPC routes; dev fallback derives from
  `SESSION_SECRET` with a WARN, like notarization.

## Keeping tests offline

The Supervisor depends only on `getAgentInvoker()`. Production returns
`A2AAgentInvoker` (real loopback HTTP); `supervisor.test.ts` injects
`inProcessAgentInvoker` via `__setAgentInvokerForTest` so it never opens a port.
The dedicated `a2a.test.ts` spins up a real ephemeral loopback server + the real
`A2AAgentInvoker`, stubbing only the LLM via the runtime seam — credential-free,
matches the eval-gate discipline.
