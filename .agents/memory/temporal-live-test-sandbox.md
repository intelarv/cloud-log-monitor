---
name: Live Temporal worker not runnable in dev sandbox
description: Why the native @temporalio worker can't be executed live here, and the patterns that DO work for verifying it
---

# Running a live Temporal cluster + native worker in the Replit dev sandbox

**Constraint:** A bash tool call that spins up `temporal server start-dev` AND a native
`@temporalio/worker` Worker gets OOM-killed (exit 137) under host memory pressure
(host frequently sits ~55/64 GB used; only ~9 GB free is variable/shared). Every
full live-worker run died this way. `bundleWorkflowCode` (webpack only, no server,
no Worker) runs fine (~5 s, 1.48 MB) — it's the *server + native core together*
that OOMs.

**Why it matters:** Don't keep retrying live-worker execution here expecting it to
pass; it's an environment ceiling, not a code bug. Verify via the gated test
(`temporal-integration.test.ts`, `pnpm --filter @workspace/api-server run test:temporal`)
on an adequately-resourced machine instead.

**Two sandbox gotchas that wasted many attempts (apply to any long/heavy bash work):**
- A bash call that is **killed** (timeout 124, or SIGKILL 137) **rolls back its
  filesystem writes** — files written via `>` redirect or `appendFileSync` during a
  killed call do NOT persist to later calls. Only a *cleanly-exiting* call (rc 0)
  preserves its output/files. So "write incrementally, kill, read the log next call"
  does not work. Make the command finish cleanly: add an in-script watchdog
  (`setTimeout(()=>process.exit(), N).unref()`) and `cat` the log in the *same* call.
- `find /nix/store ...` to locate a binary can take **>30 s** (huge store) and
  silently eats the call budget. Use `command -v` or a targeted glob
  `ls -d /nix/store/*temporal-cli*/bin/temporal` instead.
- A backgrounded server's child processes can keep the call's process group alive so
  the tool waits to the budget; `setsid ... < /dev/null &` + `pkill -KILL` helps, but
  the OOM ceiling above is the real blocker.
- `timeout` can't kill node through the `tsx` wrapper (signal not propagated); run
  `node file.mts` directly (Node 24 strips TS types natively) so SIGKILL lands.
