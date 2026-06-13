// LIVE Temporal cluster integration test (opt-in, skipped by default).
//
// Unlike workflow-engine.test.ts (which injects a FAKE TemporalRuntime so the
// engine's wiring is verified WITHOUT the SDK or a server), this file drives the
// REAL `@temporalio/*` SDK against a REAL running Temporal server. It exists to
// satisfy the "verify the Temporal backend against a real cluster" pass: lazy
// SDK load, bundled-workflow resolution (the worker compiles the source
// `temporal-workflows.ts`), workflow-id idempotency on a duplicate emit, and
// worker-crash resume from the last completed activity.
//
// It is GATED on TEMPORAL_INTEGRATION=1 and a reachable TEMPORAL_ADDRESS so the
// normal `vitest run` suite and the credential-free eval gate skip it entirely
// (no server, no behavior change). Run it via:
//   pnpm --filter @workspace/api-server run test:temporal
// which starts a local `temporal server start-dev`, points this file at it, and
// tears the server down afterwards.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  TemporalWorkflowEngine,
  workflowIdFor,
  type TemporalConfig,
} from "./temporal-engine";
import type {
  BudgetCheck,
  ReviewActivities,
  ReviewJob,
  TriageStepResult,
  VerifierStepResult,
} from "./review-orchestration";

const RUN = process.env.TEMPORAL_INTEGRATION === "1";
const ADDRESS = process.env.TEMPORAL_ADDRESS ?? "127.0.0.1:7233";
const NAMESPACE = process.env.TEMPORAL_NAMESPACE ?? "default";

// A fresh task queue per run keeps concurrent/leftover executions from other
// runs out of the way; the workflow-id is what carries the idempotency anchor.
function uniqueTaskQueue(label: string): string {
  return `phi-audit-test-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function cfg(taskQueue: string): TemporalConfig {
  return { address: ADDRESS, namespace: NAMESPACE, taskQueue, tls: false };
}

const TRIAGE = { decision: "confirm", confidence: 0.9, rationale: "ok" } as never;
const VERIFIER = { agree: true, confidence: 0.9, rationale: "ok" } as never;

/** Deterministic recording activities (no DB / no LLM). In the Node SDK the
 *  worker runs activities in-process, so these closures observe every call made
 *  by the real workflow running in the worker's sandbox. */
function recordingActivities() {
  const calls: string[] = [];
  let triageCount = 0;
  let verifierCount = 0;
  let onTriage: (() => void) | undefined;
  let verifierGate: Promise<void> | undefined;

  const activities: ReviewActivities = {
    async acquireFinding(job: ReviewJob) {
      calls.push(`acquire:${job.findingId}`);
      return { id: job.findingId } as never;
    },
    async checkBudgetPre(): Promise<BudgetCheck> {
      calls.push("budgetPre");
      return { exceeded: false, tokensUsedToday: 0 };
    },
    async persistSkippedPreBudget() {
      calls.push("skipPre");
    },
    async triageStep(job: ReviewJob): Promise<TriageStepResult> {
      triageCount += 1;
      calls.push(`triage:${job.findingId}`);
      onTriage?.();
      return { triage: TRIAGE, budgetExceededAfter: false, tokensUsedToday: 1 };
    },
    async persistSkippedAfterTriage() {
      calls.push("skipAfterTriage");
    },
    async verifierStep(job: ReviewJob): Promise<VerifierStepResult> {
      verifierCount += 1;
      calls.push(`verify:${job.findingId}`);
      if (verifierGate) await verifierGate;
      return { verifier: VERIFIER };
    },
    async persistCompleted(job: ReviewJob) {
      calls.push(`completed:${job.findingId}`);
    },
    async persistFailed(job: ReviewJob) {
      calls.push(`failed:${job.findingId}`);
    },
  };

  return {
    activities,
    calls,
    counts: () => ({ triageCount, verifierCount }),
    set onTriage(fn: () => void) {
      onTriage = fn;
    },
    set verifierGate(p: Promise<void>) {
      verifierGate = p;
    },
  };
}

/** A recorder that models the REAL review-steps.ts idempotency contract so the
 *  live worker's auto-retry can be observed end-to-end: a simulated
 *  tamper-evident ledger keyed by the per-step idempotency key, plus a budget
 *  charge that — exactly like review-steps.ts — happens ONLY when the step
 *  performs the dedupe-gate ledger INSERT. A retried attempt that finds its
 *  complete-ledger entry already present recovers the verdict and never
 *  re-charges. The verifier step is rigged to throw on its first N attempts to
 *  force Temporal's bounded auto-retry (REVIEW_ACTIVITY_OPTIONS.retry), covering
 *  BOTH failure shapes the design relies on:
 *    - a transient failure BEFORE any side effect (LLM timeout / A2A blip): the
 *      attempt writes nothing and charges nothing, so the retry runs fresh;
 *    - a crash AFTER the complete-ledger write + charge (the post-write window):
 *      the entry + charge are already committed, so the retry hits the dedupe
 *      gate, recovers the verdict, and does NOT re-charge.
 *  The net of a self-healed review is therefore exactly ONE complete-ledger
 *  entry and exactly ONE charge per step, no matter how many times the activity
 *  was retried. */
function retryRecordingActivities(failVerifierAttempts: number) {
  // Simulated ledger: key -> recorded verdict. `has(key)` is the dedupe gate.
  const ledger = new Map<string, unknown>();
  // Which step performed a charge, one push per charge (review-steps charges
  // only on the dedupe-gate INSERT), so we can assert exactly-once per step.
  const charges: string[] = [];
  const calls: string[] = [];
  let verifierAttempts = 0;

  const verifierKey = (job: ReviewJob) => `verifier:${job.findingId}`;
  const triageKey = (job: ReviewJob) => `triage:${job.findingId}`;

  const activities: ReviewActivities = {
    async acquireFinding(job: ReviewJob) {
      calls.push(`acquire:${job.findingId}`);
      return { id: job.findingId } as never;
    },
    async checkBudgetPre(): Promise<BudgetCheck> {
      calls.push("budgetPre");
      return { exceeded: false, tokensUsedToday: 0 };
    },
    async persistSkippedPreBudget() {
      calls.push("skipPre");
    },
    async triageStep(job: ReviewJob): Promise<TriageStepResult> {
      calls.push(`triage:${job.findingId}`);
      // Triage succeeds first try; its dedupe-gate INSERT charges exactly once.
      if (!ledger.has(triageKey(job))) {
        ledger.set(triageKey(job), TRIAGE);
        charges.push("triage");
      }
      return { triage: TRIAGE, budgetExceededAfter: false, tokensUsedToday: 1 };
    },
    async persistSkippedAfterTriage() {
      calls.push("skipAfterTriage");
    },
    async verifierStep(job: ReviewJob): Promise<VerifierStepResult> {
      verifierAttempts += 1;
      calls.push(`verify:${job.findingId}#${verifierAttempts}`);
      // Dedupe gate: a retry that finds the prior attempt's complete-ledger
      // entry recovers the verdict WITHOUT re-calling the LLM or re-charging.
      const existing = ledger.get(verifierKey(job));
      if (existing !== undefined) return { verifier: existing as never };
      // Attempt 1: transient failure BEFORE any side effect — nothing written,
      // nothing charged. Temporal must auto-retry the activity.
      if (verifierAttempts === 1) {
        throw new Error("transient verifier failure (pre-write)");
      }
      // Later attempts: perform the complete-ledger INSERT + charge (the
      // dedupe-gate write), then — for every rigged failure beyond the first —
      // crash AFTER the write to simulate a post-write/pre-ack worker death.
      // The retry will dedupe on the entry just committed.
      ledger.set(verifierKey(job), VERIFIER);
      charges.push("verifier");
      if (verifierAttempts <= failVerifierAttempts) {
        throw new Error("crash after complete-ledger write (post-write)");
      }
      return { verifier: VERIFIER as never };
    },
    async persistCompleted(job: ReviewJob) {
      calls.push(`completed:${job.findingId}`);
    },
    async persistFailed(job: ReviewJob) {
      calls.push(`failed:${job.findingId}`);
    },
  };

  return {
    activities,
    calls,
    counts: () => ({
      verifierAttempts,
      verifierLedgerEntries: [...ledger.keys()].filter((k) =>
        k.startsWith("verifier:"),
      ).length,
      verifierCharges: charges.filter((c) => c === "verifier").length,
      triageCharges: charges.filter((c) => c === "triage").length,
    }),
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(
  pred: () => boolean,
  timeoutMs = 30_000,
  stepMs = 50,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await sleep(stepMs);
  }
}

// Long per-test timeout: the worker compiles (bundles) the workflow module on
// first start, which is the slowest step.
const T = 120_000;

describe.skipIf(!RUN)("Temporal engine against a live cluster", () => {
  beforeAll(async () => {
    // Fail loudly (not silently skip) if the gate is on but no server answers,
    // so a misconfigured CI run is visible rather than a false green.
    const clientMod = (await import("@temporalio/client")) as any;
    const conn = await clientMod.Connection.connect({ address: ADDRESS });
    await conn.close();
  }, T);

  it(
    "drives a finding through the real workflow + worker with the in-process activity sequence",
    async () => {
      const rec = recordingActivities();
      const engine = new TemporalWorkflowEngine(
        cfg(uniqueTaskQueue("e2e")),
        rec.activities,
      );
      await engine.start();
      try {
        engine.submitReview("f-e2e", "t1");
        await waitFor(() => rec.calls.includes("completed:f-e2e"));
        // Identical sequence to InProcessWorkflowEngine's happy path.
        expect(rec.calls).toEqual([
          "acquire:f-e2e",
          "budgetPre",
          "triage:f-e2e",
          "verify:f-e2e",
          "completed:f-e2e",
        ]);
        expect(rec.counts()).toEqual({ triageCount: 1, verifierCount: 1 });
      } finally {
        await engine.stop();
      }
    },
    T,
  );

  it(
    "dedupes a duplicate emit via workflow-id idempotency (AlreadyStarted)",
    async () => {
      const rec = recordingActivities();
      // Hold the workflow open on its verifier step so the duplicate emit lands
      // while the first execution is still RUNNING (the strongest idempotency
      // case: same workflow-id, still open).
      let release: () => void = () => {};
      rec.verifierGate = new Promise<void>((r) => {
        release = r;
      });
      const engine = new TemporalWorkflowEngine(
        cfg(uniqueTaskQueue("dedupe")),
        rec.activities,
      );
      await engine.start();
      try {
        engine.submitReview("f-dup", "t1");
        await waitFor(() => rec.calls.includes("verify:f-dup"));
        // Duplicate emit for the SAME finding -> same workflow-id -> the second
        // start must be swallowed as AlreadyStarted (no second execution).
        engine.submitReview("f-dup", "t1");
        await sleep(1500);
        release();
        await waitFor(() => rec.calls.includes("completed:f-dup"));
        expect(rec.counts()).toEqual({ triageCount: 1, verifierCount: 1 });
        expect(
          rec.calls.filter((c) => c === "acquire:f-dup"),
        ).toHaveLength(1);
      } finally {
        release();
        await engine.stop();
      }
    },
    T,
  );

  it(
    "resumes from the last completed activity after a worker crash",
    async () => {
      const taskQueue = uniqueTaskQueue("resume");
      const clientMod = (await import("@temporalio/client")) as any;
      const workerMod = (await import("@temporalio/worker")) as any;
      const { fileURLToPath } = await import("node:url");
      const path = await import("node:path");
      const workflowsPath = path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "temporal-workflows.ts",
      );

      const connection = await clientMod.Connection.connect({ address: ADDRESS });
      const client = new clientMod.Client({ connection, namespace: NAMESPACE });

      // Shared recorder across BOTH workers so we can prove the post-restart
      // worker reuses the triage result from history (no re-run) and only the
      // verifier runs after the crash.
      const rec = recordingActivities();
      // Worker #1 signals when triage completes, then we crash it BEFORE the
      // verifier is dispatched -> the verifier activity never starts on #1.
      let triaged: () => void = () => {};
      const triageDone = new Promise<void>((r) => {
        triaged = r;
      });
      rec.onTriage = () => triaged();

      // The worker needs its own NativeConnection.
      const nativeConn1 = await workerMod.NativeConnection.connect({
        address: ADDRESS,
      });
      const worker1 = await workerMod.Worker.create({
        connection: nativeConn1,
        namespace: NAMESPACE,
        taskQueue,
        workflowsPath,
        activities: rec.activities,
      });
      const worker1Run = worker1.run();

      const findingId = "f-resume";
      const tenantId = "t1";
      const workflowId = workflowIdFor(tenantId, findingId);
      await client.workflow.start("reviewFindingWorkflow", {
        workflowId,
        taskQueue,
        args: [{ findingId, tenantId }],
      });

      // Wait until triage has completed, then hard-stop worker #1 so the
      // verifier is never dispatched to it (simulates a crash after the last
      // completed activity).
      await triageDone;
      worker1.shutdown();
      await worker1Run.catch(() => {});
      await nativeConn1.close().catch(() => {});

      const afterCrash = rec.counts();
      expect(afterCrash.triageCount).toBe(1);
      expect(afterCrash.verifierCount).toBe(0);

      // Bring up worker #2 on the same task queue: Temporal replays history
      // (triage result reused, NOT re-run) and dispatches the verifier.
      const nativeConn2 = await workerMod.NativeConnection.connect({
        address: ADDRESS,
      });
      const worker2 = await workerMod.Worker.create({
        connection: nativeConn2,
        namespace: NAMESPACE,
        taskQueue,
        workflowsPath,
        activities: rec.activities,
      });
      const worker2Run = worker2.run();
      try {
        const handle = client.workflow.getHandle(workflowId);
        await handle.result();
        const final = rec.counts();
        // triage ran exactly once total (history reuse, not re-run on restart),
        // verifier ran exactly once on worker #2 -> resumed, not lost, not
        // duplicated.
        expect(final.triageCount).toBe(1);
        expect(final.verifierCount).toBe(1);
        expect(rec.calls).toContain("completed:f-resume");
      } finally {
        worker2.shutdown();
        await worker2Run.catch(() => {});
        await nativeConn2.close().catch(() => {});
        await connection.close().catch(() => {});
      }
    },
    T,
  );

  it(
    "self-heals a transient activity failure via auto-retry with exactly-once side effects",
    async () => {
      // Rig the verifier to fail on its first two attempts (attempt 1 = a
      // transient pre-write failure; attempt 2 = a crash AFTER the
      // complete-ledger write + charge) and succeed on attempt 3 by deduping on
      // the entry committed in attempt 2. This drives the REAL worker's bounded
      // auto-retry (REVIEW_ACTIVITY_OPTIONS: maximumAttempts=5) against a live
      // cluster — the guarantee that was previously only unit-tested by invoking
      // the steps twice in-process (supervisor.test.ts).
      const rec = retryRecordingActivities(2);
      const engine = new TemporalWorkflowEngine(
        cfg(uniqueTaskQueue("retry")),
        rec.activities,
      );
      await engine.start();
      try {
        engine.submitReview("f-retry", "t1");
        await waitFor(() => rec.calls.includes("completed:f-retry"), 90_000);

        const c = rec.counts();
        // The verifier activity was retried (failed twice, succeeded on #3)...
        expect(c.verifierAttempts).toBe(3);
        // ...yet self-healed to completion: it never fell through to persistFailed.
        expect(rec.calls).toContain("completed:f-retry");
        expect(rec.calls).not.toContain("failed:f-retry");
        // Exactly ONE complete-ledger entry for the verifier despite 3 attempts.
        expect(c.verifierLedgerEntries).toBe(1);
        // Exactly ONE budget charge for each step — the dedupe gate suppressed
        // the re-charge on the retry that recovered the recorded verdict.
        expect(c.verifierCharges).toBe(1);
        expect(c.triageCharges).toBe(1);
      } finally {
        await engine.stop();
      }
    },
    T,
  );
});
