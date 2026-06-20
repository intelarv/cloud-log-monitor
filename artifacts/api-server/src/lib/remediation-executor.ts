// RemediationExecutor seam (Task: executing remediation worker).
//
// The HITL remediation plane stops at CONFIRMED by design — `propose_remediation`
// writes an inert proposal, a human confirms it (step-up gated), and that is
// where the system historically stopped (the actual acting step was operator /
// out-of-band). This seam is the OPTIONAL bridge from "authorized" to "acted
// on": when (and only when) an operator selects an executor via
// `REMEDIATION_EXECUTOR`, the executing worker (remediation-worker.ts) picks up
// CONFIRMED rows and runs the authorized action through one of these
// implementations.
//
// Default-inert, mirroring every other optional/cloud seam in this codebase
// (RAW_EVIDENCE_PROVIDER / SEARCH_PROVIDER / LOG_BUS_PROVIDER / NER_PROVIDER …):
//   - unset | "none"      -> null  (NO worker scheduled; confirmed proposals stay
//                            confirmed; behavior byte-identical to pre-seam, so
//                            the credential-free eval gate is unchanged).
//   - "noop" | "dev"      -> DevNoopExecutor (marks the proposal executed with a
//                            synthetic external_ref; performs NO real I/O).
//   - "channel-send"      -> ChannelSendExecutor (the `notify_owner` action:
//                            emits a PHI-safe alertable ledger event the existing
//                            post-commit dispatch hook fans out to channels).
//   - "github"            -> GitHubIssueExecutor (the `open_pr` family: opens a
//                            tracking ISSUE — the agent plane authors no code
//                            diffs — via the lazy, optional `@octokit/rest`).
//   - "redaction-queue"   -> RedactionQueueExecutor (the `redact_at_source`
//                            action: enqueues a row for an out-of-band operator
//                            drainer; the agent plane never deletes at source).
//   - "routed"            -> RoutingRemediationExecutor (per-action_type map over
//                            the three real backends; the recommended prod mode).
//
// SAFETY POSTURE. A confused-deputy that can mutate infra is the highest-blast-
// radius surface in the threat model, so every real backend is bounded:
//   - the agent plane NEVER executes (HITL preserved): a human must CONFIRM
//     first, and only then does the leader-locked, CAS-guarded worker call here.
//   - no backend writes code or deletes cloud data directly. GitHub opens an
//     *issue* (a tracking artifact, no diff); redact-at-source *enqueues* a
//     request for a separately-credentialed operator process.
//   - any payload leaving a BAA boundary (the GitHub issue body) is RE-SCANNED
//     for PHI here and refused on a hit, even though `summary`/`rationale` were
//     already scanned at the propose boundary (defense-in-depth, mirroring the
//     channel outbound PHI hard gate).
//
// PHI posture: the worker only ever hands an executor the redacted, tool-arg-
// revalidated `summary`/`rationale` (already scanned at the propose boundary) and
// ids — never `raw_evidence`. Executors MUST treat their input as the only data
// they get and MUST NOT reach back into raw finding storage.

import { redactionRequestsTable } from "@workspace/db";
import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { hasConfiguredChannels } from "./channels";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
import { scanForPhi } from "./redact";

/** The redacted, PHI-safe projection of a CONFIRMED proposal handed to an
 *  executor. No raw evidence, no finding internals — only the agent-authored
 *  (and already PHI-scanned) action description plus ids for correlation. */
export interface RemediationExecutionInput {
  proposalId: string;
  tenantId: string;
  findingId: string;
  actionType: string;
  summary: string;
  rationale: string;
}

/** Outcome of one execution attempt. `ok` carries an optional `externalRef`
 *  (e.g. a PR URL / ticket id / change id) that becomes the row's idempotency
 *  anchor; `!ok` carries a bounded, PHI-safe `reason` recorded in
 *  `execution_error` and surfaced (counts/static reason only) on the ledger. */
export type RemediationExecutionResult =
  | { ok: true; externalRef?: string }
  | { ok: false; reason: string };

export interface RemediationExecutor {
  /** Stable label recorded on the row (`executor_kind`) + ledger for
   *  attribution. */
  readonly kind: string;
  /** Run the authorized action. MUST be safe to call at most once per proposal
   *  (the worker CAS-guards confirmed→executing before calling, and records
   *  executed_at+external_ref so it is never re-invoked), but SHOULD also be
   *  internally idempotent where the backend supports it. */
  execute(input: RemediationExecutionInput): Promise<RemediationExecutionResult>;
}

/** Dev/test executor: performs NO real I/O, just reports success with a
 *  synthetic external_ref so the full confirmed→executing→executed pipeline can
 *  be exercised offline without touching any external system. */
export class DevNoopExecutor implements RemediationExecutor {
  readonly kind = "noop";
  async execute(
    input: RemediationExecutionInput,
  ): Promise<RemediationExecutionResult> {
    return { ok: true, externalRef: `noop:${input.proposalId}` };
  }
}

// ---------------------------------------------------------------------------
// channel-send (the `notify_owner` action)
// ---------------------------------------------------------------------------

/** Realizes the `notify_owner` action by emitting a PHI-safe, alertable
 *  `remediation.notify_dispatched` ledger event. The existing post-commit
 *  dispatch hook (ledger.ts → channels/dispatch.ts) fans that event out to the
 *  configured channels, which reuses ALL FIVE channel hard guarantees (outbound
 *  PHI hard gate, self-recursion guard, per-channel rate limit, webhook host
 *  allow-list + HMAC, adapter failure isolation) for free. The emitted event
 *  carries ONLY ids + the categorical action_type — no free text — so it can
 *  never carry PHI across the channel boundary.
 *
 *  Fail-closed: if no channels are configured the executor returns ok:false so
 *  the row lands in `execution_failed` (operator-visible) rather than silently
 *  "succeeding" a notification that reached nobody. */
export class ChannelSendExecutor implements RemediationExecutor {
  readonly kind = "channel-send";
  constructor(
    private readonly deps: {
      append?: typeof appendLedger;
      channelsConfigured?: () => boolean;
    } = {},
  ) {}

  async execute(
    input: RemediationExecutionInput,
  ): Promise<RemediationExecutionResult> {
    const channelsConfigured =
      this.deps.channelsConfigured ?? hasConfiguredChannels;
    if (!channelsConfigured()) {
      return { ok: false, reason: "no_channels_configured" };
    }
    const append = this.deps.append ?? appendLedger;
    await append({
      tenantId: input.tenantId,
      actor: { kind: "system", id: "remediation_executor" },
      eventType: "remediation.notify_dispatched",
      subjectType: "finding",
      subjectId: input.findingId,
      payload: {
        proposal_id: input.proposalId,
        finding_id: input.findingId,
        action_type: input.actionType,
      },
    });
    return { ok: true, externalRef: `channel-send:${input.proposalId}` };
  }
}

// ---------------------------------------------------------------------------
// github (the `open_pr` family)
// ---------------------------------------------------------------------------

/** Minimal issue-create contract, dependency-injected so the executor is unit-
 *  testable without the optional `@octokit/rest` SDK or network. */
export type GitHubIssueCreator = (params: {
  owner: string;
  repo: string;
  title: string;
  body: string;
  labels: string[];
}) => Promise<{ htmlUrl: string }>;

export interface GitHubExecutorConfig {
  token: string;
  owner: string;
  repo: string;
  labels: string[];
}

/** Default creator: lazy-imports `@octokit/rest` (an OPTIONAL dependency, same
 *  posture as the cloud SDKs / @temporalio) only when an issue is actually
 *  opened, so the package is never loaded on the default credential-free path. */
function defaultGitHubIssueCreator(token: string): GitHubIssueCreator {
  return async (params) => {
    const { Octokit } = (await import("@octokit/rest")) as {
      Octokit: new (opts: { auth: string }) => {
        rest: {
          issues: {
            create: (p: {
              owner: string;
              repo: string;
              title: string;
              body: string;
              labels: string[];
            }) => Promise<{ data: { html_url: string } }>;
          };
        };
      };
    };
    const client = new Octokit({ auth: token });
    const res = await client.rest.issues.create(params);
    return { htmlUrl: res.data.html_url };
  };
}

/** Realizes the `open_pr` / `tighten_retention` / `enable_kms` family by opening
 *  a GitHub tracking ISSUE (NOT a code PR — the agent plane deliberately never
 *  authors diffs; a human engineer turns the tracked issue into a reviewed PR).
 *  The issue body is RE-SCANNED for PHI before the (non-BAA) GitHub call and the
 *  send is refused on any hit. */
export class GitHubIssueExecutor implements RemediationExecutor {
  readonly kind = "github";
  private readonly createIssue: GitHubIssueCreator;
  constructor(
    private readonly config: GitHubExecutorConfig,
    createIssue?: GitHubIssueCreator,
  ) {
    this.createIssue =
      createIssue ?? defaultGitHubIssueCreator(config.token);
  }

  async execute(
    input: RemediationExecutionInput,
  ): Promise<RemediationExecutionResult> {
    // Defense-in-depth outbound PHI gate: this body crosses to GitHub (no BAA).
    // summary/rationale were scanned at the propose boundary, but re-scan here
    // and refuse on a hit — never leak request-derived content to the error.
    const phi = [
      ...scanForPhi(input.summary),
      ...scanForPhi(input.rationale),
    ];
    if (phi.length > 0) {
      return { ok: false, reason: "phi_in_payload" };
    }

    const title = `[remediation] ${input.actionType} for finding ${input.findingId}`;
    const body = [
      `Automated remediation tracking issue (HITL-confirmed).`,
      ``,
      `- Finding: ${input.findingId}`,
      `- Proposal: ${input.proposalId}`,
      `- Action: ${input.actionType}`,
      ``,
      `## Summary`,
      input.summary,
      ``,
      `## Rationale`,
      input.rationale,
    ].join("\n");

    try {
      const { htmlUrl } = await this.createIssue({
        owner: this.config.owner,
        repo: this.config.repo,
        title,
        body,
        labels: this.config.labels,
      });
      return { ok: true, externalRef: `github:${htmlUrl}` };
    } catch (err) {
      // Static, PHI-safe reason only. The thrown error may echo request-derived
      // content (octokit includes the request body in some errors), so we record
      // a fixed reason and log the raw error out-of-band, never on the ledger.
      logger.error({ err }, "github remediation executor failed");
      return { ok: false, reason: "github_api_error" };
    }
  }
}

// ---------------------------------------------------------------------------
// redaction-queue (the `redact_at_source` action)
// ---------------------------------------------------------------------------

/** Realizes the `redact_at_source` action by ENQUEUEING a row in
 *  `redaction_requests` for a separately-credentialed, out-of-band operator
 *  process to drain. The agent plane never deletes/mutates the cloud source
 *  directly — a confused-deputy with delete authority is the highest-blast-
 *  radius surface in the threat model. Internally idempotent: one row per
 *  proposal (unique tenant_id+proposal_id, ON CONFLICT DO NOTHING), so a retried
 *  tick re-resolves the same request id. */
export class RedactionQueueExecutor implements RemediationExecutor {
  readonly kind = "redaction-queue";

  async execute(
    input: RemediationExecutionInput,
  ): Promise<RemediationExecutionResult> {
    const requestId = await withTenant(input.tenantId, async (tx) => {
      await tx
        .insert(redactionRequestsTable)
        .values({
          id: `rq_${randomUUID()}`,
          tenantId: input.tenantId,
          findingId: input.findingId,
          proposalId: input.proposalId,
          actionType: input.actionType,
          summary: input.summary,
          rationale: input.rationale,
          status: "queued",
        })
        .onConflictDoNothing({
          target: [
            redactionRequestsTable.tenantId,
            redactionRequestsTable.proposalId,
          ],
        });
      // Resolve the canonical id (the just-inserted one, or the pre-existing one
      // on a conflict) so the external_ref idempotency anchor is stable.
      const [row] = await tx
        .select({ id: redactionRequestsTable.id })
        .from(redactionRequestsTable)
        .where(
          and(
            eq(redactionRequestsTable.tenantId, input.tenantId),
            eq(redactionRequestsTable.proposalId, input.proposalId),
          ),
        )
        .limit(1);
      return row?.id ?? null;
    });
    if (!requestId) {
      return { ok: false, reason: "redaction_enqueue_failed" };
    }
    return { ok: true, externalRef: `redaction-queue:${requestId}` };
  }
}

// ---------------------------------------------------------------------------
// routed (per-action_type fan-out over the real backends)
// ---------------------------------------------------------------------------

/** Default action_type → backend routing for `REMEDIATION_EXECUTOR=routed`.
 *  `redact_at_source` always goes to the queue; `notify_owner` to channels; the
 *  config-change family to GitHub when configured, else falls back to a channel
 *  notification (if you can't open a tracking issue, at least notify). */
export class RoutingRemediationExecutor implements RemediationExecutor {
  readonly kind = "routed";
  constructor(
    private readonly routes: Map<string, RemediationExecutor>,
    private readonly fallback: RemediationExecutor,
  ) {}

  async execute(
    input: RemediationExecutionInput,
  ): Promise<RemediationExecutionResult> {
    const executor = this.routes.get(input.actionType) ?? this.fallback;
    return executor.execute(input);
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Build the GitHub executor from env, or return null when its credentials are
 *  not fully configured. `requireConfig=true` (direct `github` selection) throws
 *  on a partial config (fail-fast); `requireConfig=false` (routed mode) returns
 *  null so routing can fall back. */
function buildGitHubExecutorFromEnv(
  env: NodeJS.ProcessEnv,
  requireConfig: boolean,
): GitHubIssueExecutor | null {
  const token = env["REMEDIATION_GITHUB_TOKEN"]?.trim();
  const owner = env["REMEDIATION_GITHUB_OWNER"]?.trim();
  const repo = env["REMEDIATION_GITHUB_REPO"]?.trim();
  if (!token || !owner || !repo) {
    if (requireConfig) {
      throw new Error(
        'REMEDIATION_EXECUTOR="github" requires REMEDIATION_GITHUB_TOKEN, ' +
          "REMEDIATION_GITHUB_OWNER and REMEDIATION_GITHUB_REPO",
      );
    }
    return null;
  }
  const labels = (env["REMEDIATION_GITHUB_LABELS"]?.trim() ?? "remediation")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return new GitHubIssueExecutor({ token, owner, repo, labels });
}

function buildRoutedExecutor(env: NodeJS.ProcessEnv): RoutingRemediationExecutor {
  const channelSend = new ChannelSendExecutor();
  const redactionQueue = new RedactionQueueExecutor();
  const github = buildGitHubExecutorFromEnv(env, false);

  const routes = new Map<string, RemediationExecutor>();
  routes.set("notify_owner", channelSend);
  routes.set("redact_at_source", redactionQueue);
  const configFamily = ["open_pr", "tighten_retention", "enable_kms", "other"];
  for (const action of configFamily) {
    routes.set(action, github ?? channelSend);
  }
  return new RoutingRemediationExecutor(routes, channelSend);
}

/** Select the executor from `REMEDIATION_EXECUTOR`. Returns `null` when unset or
 *  `"none"` — the worker treats null as "do not schedule", so the whole feature
 *  is default-inert (no behavior change, eval gate byte-identical). Throws on an
 *  unknown value (or a partially-configured backend): a misconfigured opt-in
 *  must fail fast, never silently no-op, matching the other provider seams. */
export function buildRemediationExecutorFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): RemediationExecutor | null {
  const raw = env["REMEDIATION_EXECUTOR"]?.trim().toLowerCase();
  if (!raw || raw === "none") return null;
  switch (raw) {
    case "noop":
    case "dev":
      logger.info({ executor: "noop" }, "remediation executor selected");
      return new DevNoopExecutor();
    case "channel-send":
      logger.info({ executor: "channel-send" }, "remediation executor selected");
      return new ChannelSendExecutor();
    case "github":
      logger.info({ executor: "github" }, "remediation executor selected");
      return buildGitHubExecutorFromEnv(env, true);
    case "redaction-queue":
      logger.info(
        { executor: "redaction-queue" },
        "remediation executor selected",
      );
      return new RedactionQueueExecutor();
    case "routed":
      logger.info({ executor: "routed" }, "remediation executor selected");
      return buildRoutedExecutor(env);
    default:
      throw new Error(
        `Unknown REMEDIATION_EXECUTOR "${raw}" (expected "none", "noop"/"dev", ` +
          `"channel-send", "github", "redaction-queue", "routed")`,
      );
  }
}
