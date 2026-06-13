// WorkflowEngine seam (Task: Temporal supervisor orchestration).
//
// Abstracts "start a finding-review orchestration" + engine lifecycle so the
// ledger post-commit hook dispatches through a seam instead of a concrete
// in-memory queue. Selected from `WORKFLOW_ENGINE`, mirroring the exact
// default-inert pattern of `LOG_BUS_PROVIDER` / `RAW_EVIDENCE_PROVIDER` etc:
//
//   - unset | "inprocess"  -> InProcessWorkflowEngine (DEFAULT, byte-identical
//     to the pre-seam in-memory queue; no Temporal SDK loaded).
//   - "temporal"           -> TemporalWorkflowEngine (opt-in; lazy SDK; durable
//     orchestration on an external Temporal cluster — see temporal-engine.ts).
//
// The default keeps `pnpm run eval:gate` credential-free and byte-identical.

import { logger } from "../logger";
import { runReviewOrchestration, type ReviewActivities } from "./review-orchestration";
import { inProcessReviewActivities } from "./review-steps";
import {
  TemporalWorkflowEngine,
  type TemporalConfig,
} from "./temporal-engine";

/** A long-running periodic maintenance job routed through the engine seam (the
 *  notarizer checkpoint cycle is the first one). Both the cadence (in-process)
 *  and the registered Temporal workflow are declared here so a single call site
 *  drives whichever backend is active:
 *   - in-process runs `run()` on a `setInterval` (byte-identical to the pre-seam
 *     timer it replaces);
 *   - Temporal starts `workflowType` on `cronSchedule` with a fixed workflow id
 *     derived from `name`, so the job gets durable single-execution + crash
 *     resume and IGNORES `run()` (the work happens in the registered workflow's
 *     activities on the cluster). */
export interface PeriodicJob {
  /** Stable identity: in-process log label + Temporal cron workflow-id seed. */
  name: string;
  /** In-process tick cadence in ms. */
  intervalMs: number;
  /** Temporal cron schedule (5-field cron) — the production cadence knob. */
  cronSchedule: string;
  /** Registered Temporal workflow type run on each cron tick. */
  workflowType: string;
  /** In-process unit of work per tick — must be self-contained, leader-locked,
   *  and idempotent/dedupe-guarded (the Temporal backend never calls this). */
  run: () => Promise<void>;
}

/** What the ledger hook and bootstrap depend on. `submitReview` is sync
 *  fire-and-forget (matches the old `enqueueReview`); start/stop may be async
 *  because the Temporal engine connects/disconnects a cluster.
 *  `schedulePeriodic` registers a recurring maintenance job and returns a stop
 *  handle (a no-op for the Temporal cron, which lives on the cluster by design). */
export interface WorkflowEngine {
  readonly kind: "inprocess" | "temporal";
  start(): void | Promise<void>;
  stop(): void | Promise<void>;
  submitReview(findingId: string, tenantId: string): void;
  schedulePeriodic(job: PeriodicJob): () => void;
}

// ---------------------------------------------------------------------------
// In-process engine: the original in-memory queue, behavior-preserved.
// ---------------------------------------------------------------------------

// Concurrency = 2 keeps the LLM cost bounded and avoids storms on bulk ingest
// replays. Production with a real queue (Temporal) sizes this from per-tenant
// rate limits + provider quotas.
const CONCURRENCY = 2;

export class InProcessWorkflowEngine implements WorkflowEngine {
  readonly kind = "inprocess" as const;
  private readonly pending: { findingId: string; tenantId: string }[] = [];
  private active = 0;
  // Default OFF. Production `index.ts` calls `startAgentSupervisor()` after the
  // ingest pipeline is wired; tests opt in per-test. This avoids the global
  // state bleed where one test's `finding.created` triggers an LLM call inside
  // a later test's run and pollutes the shared dev ledger.
  private stopped = true;
  private readonly activities: ReviewActivities;

  constructor(activities: ReviewActivities = inProcessReviewActivities) {
    this.activities = activities;
  }

  start(): void {
    this.stopped = false;
  }

  stop(): void {
    this.stopped = true;
    this.pending.length = 0;
  }

  submitReview(findingId: string, tenantId: string): void {
    if (this.stopped) return;
    this.pending.push({ findingId, tenantId });
    this.pump();
  }

  /** Run the job's in-process unit on a fixed interval. Independent of the
   *  review pump's `stopped` flag (the notarizer must run regardless of whether
   *  the supervisor is accepting reviews — same as the pre-seam standalone
   *  timer). `.unref()` so the timer never keeps the process alive on its own. */
  schedulePeriodic(job: PeriodicJob): () => void {
    const timer = setInterval(() => void job.run(), job.intervalMs);
    timer.unref?.();
    return () => clearInterval(timer);
  }

  private pump(): void {
    while (this.active < CONCURRENCY && this.pending.length > 0 && !this.stopped) {
      const job = this.pending.shift()!;
      this.active += 1;
      void runReviewOrchestration(job, this.activities).finally(() => {
        this.active -= 1;
        this.pump();
      });
    }
  }

  /** Test/shutdown helper: drain the queue. */
  async drain(timeoutMs = 30_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while ((this.pending.length > 0 || this.active > 0) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
  }
}

// ---------------------------------------------------------------------------
// Config + factory (mirrors log-bus-config.ts).
// ---------------------------------------------------------------------------

export type WorkflowEngineConfig =
  | { provider: "inprocess" }
  | { provider: "temporal"; config: TemporalConfig };

function boolEnv(v: string | undefined): boolean {
  if (v === undefined) return false;
  const s = v.trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

/** Parse `WORKFLOW_ENGINE` + the Temporal connection env. Fails fast (throws)
 *  when temporal is selected but `TEMPORAL_ADDRESS` is missing — same posture
 *  as the other provider seams: a misconfigured opt-in must not silently fall
 *  back to the in-process default. */
export function loadWorkflowEngineConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): WorkflowEngineConfig {
  const raw = env["WORKFLOW_ENGINE"]?.trim().toLowerCase();
  if (!raw || raw === "inprocess") return { provider: "inprocess" };
  if (raw === "temporal") {
    const address = env["TEMPORAL_ADDRESS"]?.trim();
    if (!address) {
      throw new Error(
        "WORKFLOW_ENGINE=temporal requires TEMPORAL_ADDRESS (e.g. my-namespace.acct.tmprl.cloud:7233 or temporal:7233)",
      );
    }
    return {
      provider: "temporal",
      config: {
        address,
        namespace: env["TEMPORAL_NAMESPACE"]?.trim() || "default",
        taskQueue: env["TEMPORAL_TASK_QUEUE"]?.trim() || "phi-audit-review",
        tls: boolEnv(env["TEMPORAL_TLS"]),
        apiKey: env["TEMPORAL_API_KEY"]?.trim() || undefined,
        workflowsPath: env["TEMPORAL_WORKFLOWS_PATH"]?.trim() || undefined,
      },
    };
  }
  throw new Error(`Unknown WORKFLOW_ENGINE "${raw}" (expected "inprocess" or "temporal")`);
}

export function createWorkflowEngine(cfg: WorkflowEngineConfig): WorkflowEngine {
  if (cfg.provider === "inprocess") return new InProcessWorkflowEngine();
  return new TemporalWorkflowEngine(cfg.config);
}

// ---------------------------------------------------------------------------
// Active-engine registry (singleton). Lazily defaults to in-process so tests
// (which never call init) and any pre-bootstrap caller get today's behavior.
// ---------------------------------------------------------------------------

let active: WorkflowEngine | null = null;

export function getWorkflowEngine(): WorkflowEngine {
  return active ?? (active = new InProcessWorkflowEngine());
}

export function setWorkflowEngine(engine: WorkflowEngine): void {
  active = engine;
}

/** Select + register the engine from env. Called once at bootstrap. */
export function initWorkflowEngineFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): WorkflowEngine {
  const engine = createWorkflowEngine(loadWorkflowEngineConfigFromEnv(env));
  setWorkflowEngine(engine);
  logger.info({ engine: engine.kind }, "workflow engine selected");
  return engine;
}

// ---------------------------------------------------------------------------
// Test helpers. Tests always run on the in-process engine; these resolve the
// active engine and assert that shape so the supervisor facade's start/stop/
// drain hooks keep working unchanged.
// ---------------------------------------------------------------------------

export function __getInProcessEngineForTest(): InProcessWorkflowEngine {
  const e = getWorkflowEngine();
  if (e instanceof InProcessWorkflowEngine) return e;
  const fresh = new InProcessWorkflowEngine();
  setWorkflowEngine(fresh);
  return fresh;
}

export function __resetWorkflowEngineForTest(): void {
  active = null;
}
