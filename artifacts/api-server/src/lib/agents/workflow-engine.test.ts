import { afterEach, describe, expect, it, vi } from "vitest";
import {
  InProcessWorkflowEngine,
  createWorkflowEngine,
  loadWorkflowEngineConfigFromEnv,
  type PeriodicJob,
} from "./workflow-engine";
import {
  NOTARIZER_ACTIVITY_OPTIONS,
  runNotarizerCycle,
  type NotarizerActivities,
} from "./notarizer-workflow";
import {
  TemporalWorkflowEngine,
  workflowIdFor,
  type StartWorkflowArgs,
  type TemporalConfig,
  type TemporalRuntime,
  type TemporalRuntimeFactory,
} from "./temporal-engine";
import {
  REVIEW_ACTIVITY_OPTIONS,
  type ReviewActivities,
  type ReviewJob,
} from "./review-orchestration";
import type { LedgerWriteInput } from "../ledger";

// ---------------------------------------------------------------------------
// Config parsing (mirrors the LOG_BUS_PROVIDER fail-fast contract).
// ---------------------------------------------------------------------------

describe("loadWorkflowEngineConfigFromEnv", () => {
  it("defaults to inprocess when WORKFLOW_ENGINE is unset", () => {
    expect(loadWorkflowEngineConfigFromEnv({})).toEqual({ provider: "inprocess" });
  });

  it("treats explicit inprocess identically", () => {
    expect(
      loadWorkflowEngineConfigFromEnv({ WORKFLOW_ENGINE: "inprocess" }),
    ).toEqual({ provider: "inprocess" });
  });

  it("is case/space-insensitive", () => {
    expect(
      loadWorkflowEngineConfigFromEnv({ WORKFLOW_ENGINE: "  InProcess " }),
    ).toEqual({ provider: "inprocess" });
  });

  it("fails fast when temporal is selected without TEMPORAL_ADDRESS", () => {
    expect(() =>
      loadWorkflowEngineConfigFromEnv({ WORKFLOW_ENGINE: "temporal" }),
    ).toThrow(/TEMPORAL_ADDRESS/);
  });

  it("parses temporal config with defaults", () => {
    const cfg = loadWorkflowEngineConfigFromEnv({
      WORKFLOW_ENGINE: "temporal",
      TEMPORAL_ADDRESS: "temporal:7233",
    });
    expect(cfg).toEqual({
      provider: "temporal",
      config: {
        address: "temporal:7233",
        namespace: "default",
        taskQueue: "phi-audit-review",
        tls: false,
        apiKey: undefined,
        workflowsPath: undefined,
      },
    });
  });

  it("parses temporal config overrides incl. TLS booleans + api key", () => {
    const cfg = loadWorkflowEngineConfigFromEnv({
      WORKFLOW_ENGINE: "temporal",
      TEMPORAL_ADDRESS: "ns.acct.tmprl.cloud:7233",
      TEMPORAL_NAMESPACE: "prod",
      TEMPORAL_TASK_QUEUE: "reviews",
      TEMPORAL_TLS: "true",
      TEMPORAL_API_KEY: "k",
      TEMPORAL_WORKFLOWS_PATH: "/opt/wf.js",
    });
    expect(cfg).toEqual({
      provider: "temporal",
      config: {
        address: "ns.acct.tmprl.cloud:7233",
        namespace: "prod",
        taskQueue: "reviews",
        tls: true,
        apiKey: "k",
        workflowsPath: "/opt/wf.js",
      },
    });
  });

  it("rejects an unknown provider", () => {
    expect(() =>
      loadWorkflowEngineConfigFromEnv({ WORKFLOW_ENGINE: "celery" }),
    ).toThrow(/Unknown WORKFLOW_ENGINE/);
  });
});

describe("createWorkflowEngine", () => {
  it("builds the in-process engine for the default config", () => {
    const e = createWorkflowEngine({ provider: "inprocess" });
    expect(e).toBeInstanceOf(InProcessWorkflowEngine);
    expect(e.kind).toBe("inprocess");
  });

  it("builds the temporal engine for a temporal config", () => {
    const e = createWorkflowEngine({
      provider: "temporal",
      config: {
        address: "temporal:7233",
        namespace: "default",
        taskQueue: "phi-audit-review",
        tls: false,
      },
    });
    expect(e).toBeInstanceOf(TemporalWorkflowEngine);
    expect(e.kind).toBe("temporal");
  });
});

// ---------------------------------------------------------------------------
// Workflow id derivation (Temporal start-workflow idempotency anchor).
// ---------------------------------------------------------------------------

describe("workflowIdFor", () => {
  it("is deterministic for the same {tenant, finding}", () => {
    expect(workflowIdFor("t1", "f1")).toBe(workflowIdFor("t1", "f1"));
  });

  it("differs by finding and by tenant", () => {
    expect(workflowIdFor("t1", "f1")).not.toBe(workflowIdFor("t1", "f2"));
    expect(workflowIdFor("t1", "f1")).not.toBe(workflowIdFor("t2", "f1"));
  });

  it("does not collide on the delimiter (t:enant vs tenant)", () => {
    // `${tenant}:${finding}` could collide if naively concatenated; the hash of
    // distinct delimiter placements must differ.
    expect(workflowIdFor("a", "b:c")).not.toBe(workflowIdFor("a:b", "c"));
  });

  it("produces a bounded, prefixed id", () => {
    const id = workflowIdFor("tenant", "finding");
    expect(id).toMatch(/^review-[0-9a-f]{32}$/);
  });
});

// ---------------------------------------------------------------------------
// Activity retry policy (bounded self-heal + exactly-once-side-effects invariant).
// The review activities are now per-step idempotent (per-step idempotencyKey →
// ledger dedupe; budget charged after the dedupe-gate write), so the Temporal
// workflow SHOULD auto-retry them with bounded backoff to self-heal transient
// failures. The policy lives in the pure orchestration module so it is testable
// without the SDK.
// ---------------------------------------------------------------------------

describe("REVIEW_ACTIVITY_OPTIONS", () => {
  it("enables bounded automatic activity retries (transient self-heal)", () => {
    expect(REVIEW_ACTIVITY_OPTIONS.retry.maximumAttempts).toBeGreaterThan(1);
  });

  it("uses exponential backoff bounded by a maximum interval", () => {
    expect(REVIEW_ACTIVITY_OPTIONS.retry.initialInterval).toBeTruthy();
    expect(REVIEW_ACTIVITY_OPTIONS.retry.backoffCoefficient).toBeGreaterThan(1);
    expect(REVIEW_ACTIVITY_OPTIONS.retry.maximumInterval).toBeTruthy();
  });

  it("bounds each activity with a start-to-close timeout", () => {
    expect(REVIEW_ACTIVITY_OPTIONS.startToCloseTimeout).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Temporal engine lifecycle + submitReview, against a FAKE runtime (no SDK,
// no cluster). Verifies start/stop wiring, workflow-start args, and that a
// duplicate emit (AlreadyStarted) is swallowed as the idempotency guarantee.
// ---------------------------------------------------------------------------

const TEMPORAL_CFG: TemporalConfig = {
  address: "temporal:7233",
  namespace: "default",
  taskQueue: "phi-audit-review",
  tls: false,
};

function fakeRuntime() {
  const started: StartWorkflowArgs[] = [];
  let workerRan = false;
  let shutdownCalled = false;
  let resolveWorker: () => void = () => {};
  let alreadyStartedIds = new Set<string>();
  const runtime: TemporalRuntime = {
    async startWorkflow(args) {
      if (alreadyStartedIds.has(args.workflowId)) {
        const err = new Error("Workflow execution already started");
        (err as { name?: string }).name = "WorkflowExecutionAlreadyStartedError";
        throw err;
      }
      alreadyStartedIds.add(args.workflowId);
      started.push(args);
    },
    runWorker() {
      workerRan = true;
      return new Promise<void>((r) => {
        resolveWorker = r;
      });
    },
    async shutdown() {
      shutdownCalled = true;
      resolveWorker();
    },
  };
  return {
    runtime,
    started,
    get workerRan() {
      return workerRan;
    },
    get shutdownCalled() {
      return shutdownCalled;
    },
  };
}

// Drain microtasks so the fire-and-forget submitReview promise settles.
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("TemporalWorkflowEngine (fake runtime)", () => {
  it("does not build a runtime until start()", async () => {
    let factoryCalls = 0;
    const factory: TemporalRuntimeFactory = async () => {
      factoryCalls += 1;
      return fakeRuntime().runtime;
    };
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);
    expect(factoryCalls).toBe(0);
    await engine.start();
    expect(factoryCalls).toBe(1);
    await engine.stop();
  });

  it("starts the worker and a workflow per submitReview with derived id+args", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);

    await engine.start();
    expect(fake.workerRan).toBe(true);

    engine.submitReview("f1", "t1");
    await tick();

    expect(fake.started).toHaveLength(1);
    expect(fake.started[0]).toEqual({
      workflowId: workflowIdFor("t1", "f1"),
      workflowType: "reviewFindingWorkflow",
      taskQueue: "phi-audit-review",
      args: [{ findingId: "f1", tenantId: "t1" }],
    });

    await engine.stop();
    expect(fake.shutdownCalled).toBe(true);
  });

  it("swallows AlreadyStarted on a duplicate emit (idempotency)", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);
    await engine.start();

    engine.submitReview("f1", "t1");
    await tick();
    // Same finding again -> same workflowId -> runtime throws AlreadyStarted ->
    // must NOT reject/throw (fire-and-forget) and must not double-record.
    engine.submitReview("f1", "t1");
    await tick();

    expect(fake.started).toHaveLength(1);
    await engine.stop();
  });

  it("buffers submitReview before start() and flushes on start (no review loss)", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);

    // Enqueued before the worker is up (the async startup window).
    engine.submitReview("f1", "t1");
    engine.submitReview("f2", "t1");
    await tick();
    expect(fake.started).toHaveLength(0);

    // start() flushes the buffer in order.
    await engine.start();
    await tick();
    expect(fake.started.map((s) => s.workflowId)).toEqual([
      workflowIdFor("t1", "f1"),
      workflowIdFor("t1", "f2"),
    ]);
    await engine.stop();
  });

  it("buffers submitReview during the async start() window then flushes", async () => {
    const fake = fakeRuntime();
    let releaseFactory: () => void = () => {};
    const factoryGate = new Promise<void>((r) => {
      releaseFactory = r;
    });
    const factory: TemporalRuntimeFactory = async () => {
      await factoryGate;
      return fake.runtime;
    };
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);

    const startP = engine.start(); // phase = "starting", awaiting the factory
    engine.submitReview("f1", "t1"); // arrives mid-start -> buffered
    await tick();
    expect(fake.started).toHaveLength(0);

    releaseFactory();
    await startP;
    await tick();
    expect(fake.started.map((s) => s.workflowId)).toEqual([workflowIdFor("t1", "f1")]);
    await engine.stop();
  });

  it("drops submitReview after stop() (shutting down)", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);
    await engine.start();
    await engine.stop();

    engine.submitReview("f1", "t1");
    await tick();
    expect(fake.started).toHaveLength(0);
  });

  it("ledgers supervisor.review_dropped on pre-start buffer overflow", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const dropped: LedgerWriteInput[] = [];
    const ledgerWrite = async (input: LedgerWriteInput) => {
      dropped.push(input);
    };
    // The engine is never start()ed, so every submit buffers in the bounded
    // pre-start queue (cap = MAX_PENDING_SUBMITS = 10_000). Fill to the cap
    // (no drop yet), then the next submit overflows and is dropped + ledgered.
    const engine = new TemporalWorkflowEngine(
      TEMPORAL_CFG,
      undefined,
      factory,
      ledgerWrite,
    );
    for (let i = 0; i < 10_000; i++) engine.submitReview(`f${i}`, "t1");
    expect(dropped).toHaveLength(0);
    // The 10_001st submit overflows the bounded pre-start buffer.
    engine.submitReview("overflow", "t1");
    await tick();
    expect(dropped).toHaveLength(1);
    expect(dropped[0]).toMatchObject({
      tenantId: "t1",
      eventType: "supervisor.review_dropped",
      subjectType: "finding",
      subjectId: "overflow",
      payload: { reason: "prestart_buffer_overflow", max: 10_000 },
    });
  });

  it("ledgers supervisor.review_dropped on a non-idempotency startWorkflow failure", async () => {
    const fake = fakeRuntime();
    // Make startWorkflow reject with a non-AlreadyStarted error.
    const failing: TemporalRuntime = {
      ...fake.runtime,
      async startWorkflow() {
        const err = new Error("connect ECONNREFUSED");
        (err as { name?: string }).name = "TransportError";
        throw err;
      },
    };
    const factory: TemporalRuntimeFactory = async () => failing;
    const dropped: LedgerWriteInput[] = [];
    const ledgerWrite = async (input: LedgerWriteInput) => {
      dropped.push(input);
    };
    const engine = new TemporalWorkflowEngine(
      TEMPORAL_CFG,
      undefined,
      factory,
      ledgerWrite,
    );
    await engine.start();
    engine.submitReview("f1", "t1");
    await tick();
    expect(dropped).toHaveLength(1);
    expect(dropped[0]).toMatchObject({
      tenantId: "t1",
      eventType: "supervisor.review_dropped",
      subjectType: "finding",
      subjectId: "f1",
      payload: { reason: "start_workflow_failed", errorName: "TransportError" },
    });
    await engine.stop();
  });

  it("does NOT ledger a drop when startWorkflow throws AlreadyStarted (idempotency)", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const dropped: LedgerWriteInput[] = [];
    const ledgerWrite = async (input: LedgerWriteInput) => {
      dropped.push(input);
    };
    const engine = new TemporalWorkflowEngine(
      TEMPORAL_CFG,
      undefined,
      factory,
      ledgerWrite,
    );
    await engine.start();
    engine.submitReview("f1", "t1");
    await tick();
    // Duplicate emit -> AlreadyStarted -> swallowed, NOT a dropped review.
    engine.submitReview("f1", "t1");
    await tick();
    expect(dropped).toHaveLength(0);
    await engine.stop();
  });

  it("resets to idle when start() fails so a retry can start clean", async () => {
    const fake = fakeRuntime();
    let attempt = 0;
    const factory: TemporalRuntimeFactory = async () => {
      attempt += 1;
      if (attempt === 1) throw new Error("connect ECONNREFUSED");
      return fake.runtime;
    };
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);

    await expect(engine.start()).rejects.toThrow(/ECONNREFUSED/);

    // A review enqueued after the failed start is buffered (phase back to idle),
    // and a successful retry flushes it.
    engine.submitReview("f1", "t1");
    await engine.start();
    await tick();
    expect(fake.started.map((s) => s.workflowId)).toEqual([workflowIdFor("t1", "f1")]);
    await engine.stop();
  });
});

// ---------------------------------------------------------------------------
// In-process engine drives the SAME orchestration through the activities seam.
// Use a fake ReviewActivities to assert the happy-path sequence + concurrency
// without touching the DB/LLM (supervisor.test.ts covers the real activities).
// ---------------------------------------------------------------------------

function fakeActivities() {
  const calls: string[] = [];
  const triage = { rationale: "ok" } as never;
  const verifier = { rationale: "ok" } as never;
  const activities: ReviewActivities = {
    async acquireFinding(job: ReviewJob) {
      calls.push(`acquire:${job.findingId}`);
      return { id: job.findingId } as never;
    },
    async checkBudgetPre() {
      calls.push("budgetPre");
      return { exceeded: false, tokensUsedToday: 0 };
    },
    async persistSkippedPreBudget() {
      calls.push("skipPre");
    },
    async triageStep(job: ReviewJob) {
      calls.push(`triage:${job.findingId}`);
      return { triage, budgetExceededAfter: false, tokensUsedToday: 1 };
    },
    async persistSkippedAfterTriage() {
      calls.push("skipAfterTriage");
    },
    async verifierStep(job: ReviewJob) {
      calls.push(`verify:${job.findingId}`);
      return { verifier };
    },
    async persistCompleted(job: ReviewJob) {
      calls.push(`completed:${job.findingId}`);
    },
    async persistFailed(job: ReviewJob) {
      calls.push(`failed:${job.findingId}`);
    },
  };
  return { activities, calls };
}

describe("InProcessWorkflowEngine", () => {
  it("ignores submitReview while stopped (default off)", async () => {
    const fake = fakeActivities();
    const engine = new InProcessWorkflowEngine(fake.activities);
    engine.submitReview("f1", "default");
    await engine.drain(500);
    expect(fake.calls).toEqual([]);
  });

  it("runs the full acquire->budget->triage->verify->complete sequence", async () => {
    const fake = fakeActivities();
    const engine = new InProcessWorkflowEngine(fake.activities);
    engine.start();
    engine.submitReview("f1", "default");
    await engine.drain(2000);
    expect(fake.calls).toEqual([
      "acquire:f1",
      "budgetPre",
      "triage:f1",
      "verify:f1",
      "completed:f1",
    ]);
  });

  it("clears pending work on stop", async () => {
    const fake = fakeActivities();
    const engine = new InProcessWorkflowEngine(fake.activities);
    engine.start();
    engine.stop();
    engine.submitReview("f1", "default");
    await engine.drain(500);
    expect(fake.calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Periodic-job seam (schedulePeriodic). The notarizer (checkpoint create+verify)
// rides this generic capability so it can be made durable under Temporal while
// staying a plain setInterval in-process.
// ---------------------------------------------------------------------------

const NOTARIZER_PERIODIC: Omit<PeriodicJob, "run"> = {
  name: "notarizer",
  intervalMs: 5 * 60_000,
  cronSchedule: "*/5 * * * *",
  workflowType: "notarizationWorkflow",
};

describe("InProcessWorkflowEngine.schedulePeriodic", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("runs the job's unit on the configured interval and stops on the handle", () => {
    vi.useFakeTimers();
    let runs = 0;
    const engine = new InProcessWorkflowEngine(fakeActivities().activities);
    const stop = engine.schedulePeriodic({
      ...NOTARIZER_PERIODIC,
      run: async () => {
        runs += 1;
      },
    });

    expect(runs).toBe(0);
    vi.advanceTimersByTime(NOTARIZER_PERIODIC.intervalMs * 3);
    expect(runs).toBe(3);

    stop();
    vi.advanceTimersByTime(NOTARIZER_PERIODIC.intervalMs * 5);
    expect(runs).toBe(3); // halted: no further ticks after the stop handle.
  });

  it("schedules independently of the review pump's stopped flag", () => {
    vi.useFakeTimers();
    let runs = 0;
    // The engine is NOT start()ed -> review submits are ignored, but the
    // periodic notarizer must still tick (mirrors the pre-seam standalone timer).
    const engine = new InProcessWorkflowEngine(fakeActivities().activities);
    const stop = engine.schedulePeriodic({
      ...NOTARIZER_PERIODIC,
      run: async () => {
        runs += 1;
      },
    });
    vi.advanceTimersByTime(NOTARIZER_PERIODIC.intervalMs * 2);
    expect(runs).toBe(2);
    stop();
  });
});

describe("TemporalWorkflowEngine.schedulePeriodic (fake runtime)", () => {
  it("dispatches a fixed-id cron workflow with empty args", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);
    await engine.start();

    engine.schedulePeriodic({ ...NOTARIZER_PERIODIC, run: async () => {} });
    await tick();

    expect(fake.started).toHaveLength(1);
    expect(fake.started[0]).toEqual({
      workflowId: "periodic-notarizer",
      workflowType: "notarizationWorkflow",
      taskQueue: "phi-audit-review",
      args: [],
      cronSchedule: "*/5 * * * *",
    });
    await engine.stop();
  });

  it("buffers schedulePeriodic before start() and flushes the cron on start", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);

    engine.schedulePeriodic({ ...NOTARIZER_PERIODIC, run: async () => {} });
    await tick();
    expect(fake.started).toHaveLength(0);

    await engine.start();
    await tick();
    expect(fake.started.map((s) => s.workflowId)).toEqual(["periodic-notarizer"]);
    await engine.stop();
  });

  it("swallows AlreadyStarted when the cron survived a prior run (idempotency)", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);
    await engine.start();

    engine.schedulePeriodic({ ...NOTARIZER_PERIODIC, run: async () => {} });
    await tick();
    // Re-scheduling the same fixed-id cron -> runtime throws AlreadyStarted ->
    // must NOT reject/throw and must not double-record.
    engine.schedulePeriodic({ ...NOTARIZER_PERIODIC, run: async () => {} });
    await tick();
    expect(fake.started).toHaveLength(1);
    await engine.stop();
  });

  it("drops schedulePeriodic after stop()", async () => {
    const fake = fakeRuntime();
    const factory: TemporalRuntimeFactory = async () => fake.runtime;
    const engine = new TemporalWorkflowEngine(TEMPORAL_CFG, undefined, factory);
    await engine.start();
    await engine.stop();

    engine.schedulePeriodic({ ...NOTARIZER_PERIODIC, run: async () => {} });
    await tick();
    expect(fake.started).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Notarizer activity retry policy — same no-duplicate-side-effects invariant as
// the review path. The cycle appends audit-ledger checkpoint entries, so the
// Temporal workflow MUST NOT auto-retry the activity within a single tick.
// ---------------------------------------------------------------------------

describe("NOTARIZER_ACTIVITY_OPTIONS", () => {
  it("disables automatic activity retries (at-most-once-per-tick)", () => {
    expect(NOTARIZER_ACTIVITY_OPTIONS.retry.maximumAttempts).toBe(1);
  });

  it("bounds the cycle with a start-to-close timeout", () => {
    expect(NOTARIZER_ACTIVITY_OPTIONS.startToCloseTimeout).toBeTruthy();
  });
});

describe("runNotarizerCycle", () => {
  it("invokes the runCycle activity exactly once per tick", async () => {
    let cycles = 0;
    const activities: NotarizerActivities = {
      async runCycle() {
        cycles += 1;
      },
    };
    await runNotarizerCycle(activities);
    expect(cycles).toBe(1);
  });
});
