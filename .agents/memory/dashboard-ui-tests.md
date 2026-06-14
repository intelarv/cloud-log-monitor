---
name: Dashboard UI tests are committed vitest component tests
description: How "automated UI test" tasks for the dashboard must be delivered so code review accepts them
---

The dashboard has no Playwright/e2e harness — its only durable test surface is
vitest + @testing-library/react component tests under `src/**/*.test.{ts,tsx}`
(config: `artifacts/dashboard/vitest.config.ts`, jsdom, `@` alias, setup in
`src/test-setup.ts`). Run with `pnpm --filter @workspace/dashboard run test`.

**Rule:** when a task says "add automated UI tests" (even if it also says "use the
Playwright testing subagent"), the accepted *deliverable* is committed vitest
component test file(s). Running the Playwright testing subagent is fine as extra
live verification, but it leaves nothing in the diff, so a code-review gate will
REJECT the task as "primary deliverable missing."

**Why:** a prior close-out/reopen UI-test task passed eval-gate + typecheck + unit
tests but was rejected at code review because the diff contained only a bug fix and
no test files — the Playwright runs were ephemeral.

**Refinement (security-relevant DB-backed flows):** a mocked component test
alone is NOT enough when the task's core claim is a *persistence* guarantee
(e.g. "closing out a finding actually revokes the break-glass grant row"). Code
review will REJECT a component-only diff for these, demanding real HTTP + DB +
state verification + cleanup. There is no committed Playwright harness, so the
durable artifact is an **api-server route/integration test** (mirror
`src/routes/admin.auto-revoke.route.test.ts`): boot + real `fetch` against the
in-process app over the session/step-up cookie flow, inject rows via `withTenant`
(FORCE RLS needs the app.tenant_id GUC), read the row straight from the DB to
prove the state change, and clean up injected finding/grant rows in a `finally`
(never delete from append-only `ledger_entries`). Keep the component test too for
the analyst-facing toast wording — ship both layers.

**How to apply:** mirror `src/pages/finding-history-card.test.tsx` — mock
`@workspace/api-client-react` with `importOriginal` and override just the mutation
hook(s); mock `@/hooks/use-toast` to capture toast calls; render the component in a
real `QueryClientProvider` and `vi.spyOn(queryClient, "invalidateQueries")` to
assert query-key invalidation (real `getGet*QueryKey` come through the spread
mock). Drive interactions with `fireEvent` (no `@testing-library/user-event` dep)
+ `waitFor`. Radix Dialog renders in a portal but `screen` queries document.body.

**RTL rerender gotcha (cost hours):** to re-run an effect that fires on a
hook-data change (e.g. a grants-poll transition), `utils.rerender(...)` MUST be
handed a **freshly built** element each call — `const el = (<X/>); rerender(el)`
with the same reference makes React bail out (element identity unchanged), the
component never re-renders, the effect never re-runs, and the assertion fails even
though the product is fine. Build the tree from a `() => (<...>)` factory. This
masqueraded as "toast never renders" and sent me chasing a non-existent
`useToast`/`Toaster` bug; a one-consumer smoke test rendered toasts fine.

**Console output is suppressed in this vitest setup** — `console.log` /
`screen.debug()` print nothing (even for failing tests). Don't debug with logs;
assert on `document.body.innerHTML` (`expect(...).toContain(...)`) so the diff in
the failure message carries the DOM.

**Real-`Toaster` render test > mocked-`useToast` test for toast assertions:** the
mocked notice test only proves `toast()` was *called*; render the actual
`<Toaster/>` as a sibling and assert the title text is in the DOM to prove the
call→store→render path (see `finding-detail-toast-render.test.tsx`). Note live
toasts auto-dismiss at Radix's ~5s default, so a Playwright agent often can't
"see" a transient cross-analyst toast — the committed render test is the
authoritative proof, the e2e only proves the live propagation (raw unlock +
history refresh without reload).
