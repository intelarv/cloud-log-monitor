// Default-inert Temporal adapter for the WorkflowEngine seam.
//
// Opt-in via WORKFLOW_ENGINE=temporal (+ TEMPORAL_ADDRESS etc). Same posture as
// every other cloud dependency in this repo (Kafka/NATS brokers, cloud KMS,
// S3/GCS/Azure raw-evidence stores, A2A mTLS): the SDK is an OPTIONAL dependency
// loaded lazily via a variable-aliased dynamic import, so an offline install
// without `@temporalio/*` typechecks, builds, and passes the eval gate
// byte-identical — nothing here runs unless an operator selects temporal AND
// installs the SDK AND points at a real cluster.
//
// We do NOT stand up a Temporal cluster in dev. The engine is exercised by unit
// tests that inject a fake `TemporalRuntime` through the constructor seam below,
// so workflow-id derivation, start-idempotency, and lifecycle are verified
// without a live server or the SDK present.
//
// Durability model: each `finding.created` starts a Temporal Workflow whose id
// is a stable hash of {tenantId, findingId}. Temporal's start-workflow
// idempotency dedupes a duplicate emit (e.g. a double-emit on restart) on top
// of the existing DB CAS. The workflow (temporal-workflows.ts) is deterministic
// orchestration ONLY — all I/O lives in the activities (review-steps.ts), which
// the worker registers — so a worker crash resumes the workflow from its last
// completed activity instead of losing the job.

import { fileURLToPath } from "node:url";
import path from "node:path";
import { existsSync } from "node:fs";
import { logger } from "../logger";
import { appendLedger, type LedgerWriteInput } from "../ledger";
import { inProcessReviewActivities } from "./review-steps";
import { workflowIdFor } from "./workflow-id";
import type { ReviewActivities } from "./review-orchestration";
import type { PeriodicJob, WorkflowEngine } from "./workflow-engine";

// Re-exported from its own module so the review activities can derive their
// per-step idempotency keys from the same value without importing this engine
// module (circular dep). Kept exported HERE for the existing importers/tests.
export { workflowIdFor };

type LedgerWriteFn = (input: LedgerWriteInput) => Promise<unknown>;

export interface TemporalConfig {
  address: string;
  namespace: string;
  taskQueue: string;
  tls: boolean;
  apiKey?: string;
  /** Optional override for the bundled workflow module path (operator escape
   *  hatch when the auto-resolved dist path doesn't match their deploy). */
  workflowsPath?: string;
}

export interface StartWorkflowArgs {
  workflowId: string;
  workflowType: string;
  taskQueue: string;
  args: unknown[];
  /** Present for periodic jobs (schedulePeriodic) -> Temporal runs the workflow
   *  on this cron schedule. Absent for one-shot review workflows. */
  cronSchedule?: string;
}

/** The minimal Temporal surface the engine needs. The real implementation
 *  wraps `@temporalio/client` + `@temporalio/worker`; tests inject a fake. */
export interface TemporalRuntime {
  startWorkflow(args: StartWorkflowArgs): Promise<void>;
  /** Run the worker; resolves only when the worker terminates. */
  runWorker(): Promise<void>;
  shutdown(): Promise<void>;
}

export type TemporalRuntimeFactory = (
  cfg: TemporalConfig,
  activities: ReviewActivities,
) => Promise<TemporalRuntime>;

function isAlreadyStartedError(err: unknown): boolean {
  const name = (err as { name?: string })?.name ?? "";
  const msg = (err as Error)?.message ?? "";
  return (
    name === "WorkflowExecutionAlreadyStartedError" ||
    /already started|already exists/i.test(msg)
  );
}

// Variable-aliased dynamic import keeps the optional SDK out of the esbuild
// bundle and the tsc graph (same trick as cloud-log-bus.ts / a2a/transport.ts).
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

/** Resolve the bundled workflow module. In a built deploy esbuild emits
 *  `temporal-workflows.mjs` next to `index.mjs`; in source layouts the `.ts`
 *  sits beside this file. Operators can override via TEMPORAL_WORKFLOWS_PATH. */
function resolveWorkflowsPath(cfg: TemporalConfig): string {
  if (cfg.workflowsPath) return cfg.workflowsPath;
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const candidate of [
    // Source/dev layout: sibling of this module (src/lib/agents/...).
    path.join(here, "temporal-workflows.ts"),
    path.join(here, "temporal-workflows.mjs"),
    path.join(here, "temporal-workflows.js"),
    // Bundled dist layout: temporal-engine is bundled into dist/index.mjs, so
    // `here` is the dist root while esbuild emits the workflow (outbase=src) to
    // dist/lib/agents/temporal-workflows.mjs.
    path.join(here, "lib", "agents", "temporal-workflows.mjs"),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  // Fall back to the dist sibling name even if absent so the worker surfaces a
  // clear "module not found" rather than a silent no-op.
  return path.join(here, "lib", "agents", "temporal-workflows.mjs");
}

/** Default factory: lazily builds a real Temporal client + worker. Only runs
 *  when temporal is selected and the SDK is installed. */
const defaultRuntimeFactory: TemporalRuntimeFactory = async (cfg, activities) => {
  const clientMod = await loadOptional("@temporalio/client");
  const workerMod = await loadOptional("@temporalio/worker");
  const Connection = clientMod?.Connection ?? clientMod?.default?.Connection;
  const Client = clientMod?.Client ?? clientMod?.default?.Client;
  const Worker = workerMod?.Worker ?? workerMod?.default?.Worker;
  const NativeConnection =
    workerMod?.NativeConnection ?? workerMod?.default?.NativeConnection;
  if (!Connection || !Client || !Worker || !NativeConnection) {
    throw new Error(
      "WORKFLOW_ENGINE=temporal requires the optional Temporal SDK. Install: " +
        "pnpm --filter @workspace/api-server add @temporalio/client @temporalio/worker @temporalio/workflow",
    );
  }

  const tlsOpt = cfg.tls ? { tls: {} } : {};
  const apiKeyOpt = cfg.apiKey ? { apiKey: cfg.apiKey } : {};

  const connection = await Connection.connect({
    address: cfg.address,
    ...tlsOpt,
    ...apiKeyOpt,
  });
  const client = new Client({ connection, namespace: cfg.namespace });

  const workerConnection = await NativeConnection.connect({
    address: cfg.address,
    ...tlsOpt,
    ...apiKeyOpt,
  });
  // Register the notarizer activity set alongside review so the cron-driven
  // notarizationWorkflow can resolve `runCycle` on the worker. Imported lazily
  // (a local dynamic import) purely to keep this side-effecting impl off
  // temporal-engine's top-level module graph; esbuild still bundles it.
  const { inProcessNotarizerActivities } = await import("./notarizer-steps");

  const worker = await Worker.create({
    connection: workerConnection,
    namespace: cfg.namespace,
    taskQueue: cfg.taskQueue,
    workflowsPath: resolveWorkflowsPath(cfg),
    activities: { ...activities, ...inProcessNotarizerActivities },
  });

  return {
    async startWorkflow({ workflowId, workflowType, taskQueue, args, cronSchedule }) {
      await client.workflow.start(workflowType, {
        workflowId,
        taskQueue,
        args,
        ...(cronSchedule ? { cronSchedule } : {}),
      });
    },
    runWorker: () => worker.run(),
    async shutdown() {
      try {
        worker.shutdown();
      } catch {
        /* worker may not have started cleanly */
      }
      await workerConnection.close().catch(() => {});
      await connection.close().catch(() => {});
    },
  };
};

/** Cap on the pre-start buffer so a never-completing start() (or a misconfigured
 *  cluster) can't grow unbounded. Findings themselves are already persisted in
 *  the DB; an overflow drops only the *enqueue* of the agent review, loudly. */
const MAX_PENDING_SUBMITS = 10_000;

export class TemporalWorkflowEngine implements WorkflowEngine {
  readonly kind = "temporal" as const;
  private runtime: TemporalRuntime | null = null;
  /** idle -> starting -> running -> stopped. submitReview buffers while
   *  idle/starting (the async start() window), dispatches while running, and
   *  drops while stopped (shutdown in progress). */
  private phase: "idle" | "starting" | "running" | "stopped" = "idle";
  private readonly pending: Array<{ findingId: string; tenantId: string }> = [];
  /** Periodic jobs registered before the worker is up (the async start() window);
   *  flushed into cron workflows once running, like `pending` for reviews. */
  private readonly pendingPeriodic: PeriodicJob[] = [];
  private readonly cfg: TemporalConfig;
  private readonly activities: ReviewActivities;
  private readonly factory: TemporalRuntimeFactory;
  private readonly ledgerWrite: LedgerWriteFn;

  constructor(
    cfg: TemporalConfig,
    activities: ReviewActivities = inProcessReviewActivities,
    factory: TemporalRuntimeFactory = defaultRuntimeFactory,
    ledgerWrite: LedgerWriteFn = appendLedger,
  ) {
    this.cfg = cfg;
    this.activities = activities;
    this.factory = factory;
    this.ledgerWrite = ledgerWrite;
  }

  /** Surface a dropped/undispatched supervisor review on the tamper-evident
   *  ledger so operators are paged (`supervisor.review_dropped` is wired into
   *  ALERT_RULES at `high`) instead of discovering the loss in logs. For a
   *  compliance system a dropped review means a finding silently never got its
   *  Triage->Verifier verdict. Tenant-scoped (we know the dropped job's
   *  tenant); payload carries only the finding id + a static reason (+ the
   *  config knob / error name), never any attacker-influenced data or PHI. The
   *  write is fire-and-forget and `.catch`-isolated so a slow/failing ledger
   *  can neither block the (already-completed) drop nor throw out of the
   *  sync `submitReview` / fire-and-forget `dispatch` paths. The writer is
   *  injected (default = real `appendLedger`) so tests assert it without a DB. */
  private ledgerReviewDropped(
    findingId: string,
    tenantId: string,
    reason: string,
    extra: Record<string, unknown> = {},
  ): void {
    void this.ledgerWrite({
      tenantId,
      actor: { kind: "system", id: "temporal_engine" },
      eventType: "supervisor.review_dropped",
      subjectType: "finding",
      subjectId: findingId,
      payload: { reason, ...extra },
    }).catch((err: unknown) => {
      logger.error({ err, findingId }, "failed to ledger supervisor.review_dropped");
    });
  }

  async start(): Promise<void> {
    if (this.phase === "running" || this.phase === "starting") return;
    this.phase = "starting";
    try {
      this.runtime = await this.factory(this.cfg, this.activities);
    } catch (err) {
      // Reset so a retry can start cleanly; surface the failure to the caller
      // (startAgentSupervisor fails boot closed on temporal).
      this.phase = "idle";
      throw err;
    }
    // Run the worker in the background; it resolves only on shutdown.
    void this.runtime.runWorker().catch((err) => {
      logger.error({ err }, "temporal worker terminated unexpectedly");
    });
    this.phase = "running";
    logger.info(
      { namespace: this.cfg.namespace, taskQueue: this.cfg.taskQueue },
      "temporal workflow engine started",
    );
    // Flush anything enqueued during the async startup window so a
    // finding.created that arrived before the worker was up is not lost.
    const buffered = this.pending.splice(0, this.pending.length);
    for (const job of buffered) this.dispatch(job.findingId, job.tenantId);
    // Same for periodic jobs registered before the worker was up.
    const periodic = this.pendingPeriodic.splice(0, this.pendingPeriodic.length);
    for (const job of periodic) this.dispatchPeriodic(job);
  }

  async stop(): Promise<void> {
    const wasRunning = this.phase === "running" && this.runtime !== null;
    this.phase = "stopped";
    this.pending.length = 0;
    this.pendingPeriodic.length = 0;
    if (!wasRunning || !this.runtime) return;
    await this.runtime.shutdown();
    this.runtime = null;
  }

  submitReview(findingId: string, tenantId: string): void {
    if (this.phase === "running" && this.runtime) {
      this.dispatch(findingId, tenantId);
      return;
    }
    if (this.phase === "stopped") {
      logger.warn({ findingId }, "temporal engine stopped; dropping submitReview");
      return;
    }
    // idle/starting: buffer until the worker is up so the async startup window
    // doesn't lose reviews. Bounded to avoid unbounded growth if start stalls.
    if (this.pending.length >= MAX_PENDING_SUBMITS) {
      logger.error(
        { findingId, max: MAX_PENDING_SUBMITS },
        "temporal pre-start buffer full; dropping submitReview",
      );
      this.ledgerReviewDropped(findingId, tenantId, "prestart_buffer_overflow", {
        max: MAX_PENDING_SUBMITS,
      });
      return;
    }
    this.pending.push({ findingId, tenantId });
  }

  schedulePeriodic(job: PeriodicJob): () => void {
    if (this.phase === "running" && this.runtime) {
      this.dispatchPeriodic(job);
    } else if (this.phase === "stopped") {
      logger.warn({ job: job.name }, "temporal engine stopped; dropping schedulePeriodic");
    } else {
      // idle/starting: buffer until the worker is up, then flush in start().
      this.pendingPeriodic.push(job);
    }
    // The Temporal cron workflow persists on the cluster across app restarts —
    // that durability IS the point — so the app-side stop handle is a no-op.
    return () => {};
  }

  private dispatchPeriodic(job: PeriodicJob): void {
    const runtime = this.runtime;
    if (!runtime) return;
    void runtime
      .startWorkflow({
        // Fixed id -> a restart re-issuing the same cron schedule hits
        // AlreadyStarted (swallowed below) instead of spawning a duplicate.
        workflowId: `periodic-${job.name}`,
        workflowType: job.workflowType,
        taskQueue: this.cfg.taskQueue,
        args: [],
        cronSchedule: job.cronSchedule,
      })
      .catch((err) => {
        // The cron is already scheduled (e.g. survived a prior run) -> that is
        // the idempotency guarantee; swallow it quietly.
        if (isAlreadyStartedError(err)) return;
        logger.error({ err, job: job.name }, "temporal schedulePeriodic failed");
      });
  }

  private dispatch(findingId: string, tenantId: string): void {
    const runtime = this.runtime;
    if (!runtime) return;
    const workflowId = workflowIdFor(tenantId, findingId);
    void runtime
      .startWorkflow({
        workflowId,
        workflowType: "reviewFindingWorkflow",
        taskQueue: this.cfg.taskQueue,
        args: [{ findingId, tenantId }],
      })
      .catch((err) => {
        // Duplicate emit for the same finding -> Temporal refuses the second
        // start. That IS the idempotency guarantee; swallow it quietly.
        if (isAlreadyStartedError(err)) return;
        logger.error({ err, findingId }, "temporal startWorkflow failed");
        // A non-idempotency start failure means this finding's review was never
        // dispatched (dispatch is fire-and-forget with no retry). Surface it so
        // operators are paged rather than finding the gap in logs.
        this.ledgerReviewDropped(findingId, tenantId, "start_workflow_failed", {
          errorName: (err as { name?: string })?.name ?? "Error",
        });
      });
  }
}
