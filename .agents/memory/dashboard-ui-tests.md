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

**How to apply:** mirror `src/pages/finding-history-card.test.tsx` — mock
`@workspace/api-client-react` with `importOriginal` and override just the mutation
hook(s); mock `@/hooks/use-toast` to capture toast calls; render the component in a
real `QueryClientProvider` and `vi.spyOn(queryClient, "invalidateQueries")` to
assert query-key invalidation (real `getGet*QueryKey` come through the spread
mock). Drive interactions with `fireEvent` (no `@testing-library/user-event` dep)
+ `waitFor`. Radix Dialog renders in a portal but `screen` queries document.body.
