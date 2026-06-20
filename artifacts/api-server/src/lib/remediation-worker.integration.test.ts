// Integration coverage for the executing remediation worker. Hits the shared
// dev Postgres, so it follows the M1.9 isolation discipline (per-test tenant via
// uniqueTenant, head-seq scoping for ledger assertions — see ledger-harness.ts).
//
// Verifies the full confirmed→executing→executed|execution_failed pipeline:
//   - a CONFIRMED proposal is claimed and driven to `executed` with an
//     external_ref + executor_kind, ledgering `remediation.executed`;
//   - a failing executor drives the row to `execution_failed` with a bounded
//     execution_error, ledgering `remediation.execution_failed`;
//   - a null executor (default-inert) is a no-op: confirmed rows stay confirmed.

import { describe, it, expect, beforeAll } from "vitest";
import { and, desc, eq, gt } from "drizzle-orm";
import { sql } from "drizzle-orm";
import {
  db,
  bootstrap,
  findingsTable,
  ledgerEntriesTable,
  remediationProposalsTable,
} from "@workspace/db";
import { withTenant } from "./db-context";
import { proposeRemediationTool } from "./tools";
import { runRemediationExecutionOnce } from "./remediation-worker";
import {
  DevNoopExecutor,
  type RemediationExecutor,
} from "./remediation-executor";
import { uniq, ledgerHeadSeq, uniqueTenant } from "../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

async function createFinding(tenantId: string): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(tenantId, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      source: `fixture:rem-worker:${uniq()}`,
      fingerprint: `phi:ssn:rem-worker:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Create a CONFIRMED proposal: propose (PENDING) then CAS it to confirmed,
 *  exactly the state the executing worker is meant to pick up. */
async function createConfirmedProposal(
  tenantId: string,
  findingId: string,
): Promise<string> {
  const out = await proposeRemediationTool.handler(
    {
      finding_id: findingId,
      action_type: "notify_owner",
      summary: "Notify the billing service owner",
      rationale: "Repeated PHI in this log group; owner should rotate retention",
    },
    { tenantId, userId: "agent-driver", agent: "chat", onPolicyViolation: async () => {} },
  );
  await withTenant(tenantId, async (tx) => {
    await tx.execute(sql`
      UPDATE remediation_proposals
      SET status = 'confirmed', decided_by_user_id = 'human-1', decided_at = now()
      WHERE id = ${out.proposal_id} AND status = 'pending'
    `);
  });
  return out.proposal_id;
}

async function getProposal(tenantId: string, id: string) {
  return withTenant(tenantId, async (tx) => {
    const rows = await tx
      .select()
      .from(remediationProposalsTable)
      .where(eq(remediationProposalsTable.id, id))
      .limit(1);
    return rows[0]!;
  });
}

async function ledgerExists(
  eventType: string,
  subjectId: string,
  sinceSeq: number,
): Promise<boolean> {
  const rows = await db
    .select({ seq: ledgerEntriesTable.seq })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, eventType),
        eq(ledgerEntriesTable.subjectId, subjectId),
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  return rows.length > 0;
}

const failingExecutor: RemediationExecutor = {
  kind: "noop",
  async execute() {
    return { ok: false, reason: "simulated_failure" };
  },
};

const throwingExecutor: RemediationExecutor = {
  kind: "noop",
  async execute() {
    throw new Error("boom with maybe-PHI 123-45-6789 in message");
  },
};

// An executor whose declared failure reason embeds a PHI/secret-like token —
// must never reach execution_error verbatim.
const phiReasonExecutor: RemediationExecutor = {
  kind: "noop",
  async execute() {
    return { ok: false, reason: "backend rejected patient SSN 123-45-6789" };
  },
};

// A hostile executor that throws an error whose *name* embeds PHI — `err.name`
// must be sanitized just like the declared-reason path.
const phiThrowNameExecutor: RemediationExecutor = {
  kind: "noop",
  async execute() {
    const e = new Error("opaque");
    e.name = "FailureForSSN_123-45-6789";
    throw e;
  },
};

describe("runRemediationExecutionOnce", () => {
  it("drives a CONFIRMED proposal to executed + ledgers remediation.executed", async () => {
    const tenantId = uniqueTenant("rem-exec-ok");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);
    const sinceSeq = await ledgerHeadSeq();

    const summary = await runRemediationExecutionOnce(new DevNoopExecutor());
    expect(summary.executed).toBeGreaterThanOrEqual(1);

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("executed");
    expect(row.externalRef).toBe(`noop:${proposalId}`);
    expect(row.executorKind).toBe("noop");
    expect(row.executedAt).not.toBeNull();
    expect(row.executionError).toBeNull();

    expect(await ledgerExists("remediation.executed", findingId, sinceSeq)).toBe(
      true,
    );
  });

  it("drives a failing execution to execution_failed + ledgers the failure", async () => {
    const tenantId = uniqueTenant("rem-exec-fail");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);
    const sinceSeq = await ledgerHeadSeq();

    const summary = await runRemediationExecutionOnce(failingExecutor);
    expect(summary.failed).toBeGreaterThanOrEqual(1);

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("execution_failed");
    expect(row.executionError).toBe("simulated_failure");
    expect(row.executedAt).not.toBeNull();

    expect(
      await ledgerExists("remediation.execution_failed", findingId, sinceSeq),
    ).toBe(true);
  });

  it("normalizes a thrown executor error to a static PHI-safe reason", async () => {
    const tenantId = uniqueTenant("rem-exec-throw");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);

    await runRemediationExecutionOnce(throwingExecutor);

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("execution_failed");
    // Neither the thrown message NOR the error name (both executor-controlled,
    // both potential PHI sinks) is recorded — only a fixed constant.
    expect(row.executionError).toBe("executor_threw");
    expect(row.executionError).not.toContain("123-45-6789");
  });

  it("sanitizes a PHI-bearing executor failure reason before persisting it", async () => {
    const tenantId = uniqueTenant("rem-exec-phireason");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);

    await runRemediationExecutionOnce(phiReasonExecutor);

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("execution_failed");
    // The raw reason embedded an SSN-like token; it must be replaced wholesale,
    // never persisted verbatim.
    expect(row.executionError).toBe("redacted_unsafe_reason");
    expect(row.executionError).not.toContain("123-45-6789");
  });

  it("never persists a PHI-bearing thrown Error.name (glued token would evade the scanner)", async () => {
    const tenantId = uniqueTenant("rem-exec-phithrow");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);

    await runRemediationExecutionOnce(phiThrowNameExecutor);

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("execution_failed");
    // The thrown path emits a fixed constant, so an SSN glued into err.name
    // (which has no word boundary for the PHI scanner) can never leak.
    expect(row.executionError).toBe("executor_threw");
    expect(row.executionError).not.toContain("123-45-6789");
  });

  it("recovers a row stranded in 'executing' (crash mid-execute) on a later sweep", async () => {
    const tenantId = uniqueTenant("rem-exec-stale");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);

    // Simulate a crash: the row was claimed (executing) long ago but never
    // finalized — executed_at is well past the stale threshold.
    await withTenant(tenantId, async (tx) => {
      await tx.execute(sql`
        UPDATE remediation_proposals
        SET status = 'executing', executed_at = now() - interval '1 hour', executor_kind = 'noop'
        WHERE id = ${proposalId}
      `);
    });

    const summary = await runRemediationExecutionOnce(new DevNoopExecutor());
    expect(summary.executed).toBeGreaterThanOrEqual(1);

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("executed");
    expect(row.externalRef).toBe(`noop:${proposalId}`);
  });

  it("never re-acts on an already-executed proposal (poll selects only confirmed)", async () => {
    const tenantId = uniqueTenant("rem-exec-idem");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);
    // Drive it to a terminal `executed` state, as a prior successful sweep would
    // have — with an external_ref distinct from what THIS sweep would write.
    await withTenant(tenantId, async (tx) => {
      await tx.execute(sql`
        UPDATE remediation_proposals
        SET status = 'executed', executed_at = now() - interval '5 minutes',
            external_ref = 'noop:prior-run', executor_kind = 'noop'
        WHERE id = ${proposalId}
      `);
    });
    const before = await getProposal(tenantId, proposalId);

    await runRemediationExecutionOnce(new DevNoopExecutor());

    const after = await getProposal(tenantId, proposalId);
    // The terminal row is untouched: a re-execute would overwrite external_ref
    // with `noop:<id>` and bump executed_at. Idempotency = the poll only ever
    // claims `confirmed`, so an executed row is never re-acted-on.
    expect(after.status).toBe("executed");
    expect(after.externalRef).toBe("noop:prior-run");
    expect(after.executedAt?.getTime()).toBe(before.executedAt?.getTime());
  });

  it("leaves a recently-claimed 'executing' row alone (not reset before the stale threshold)", async () => {
    const tenantId = uniqueTenant("rem-exec-fresh");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);
    // Claimed seconds ago: a live worker may be mid-execute. The stale-recovery
    // reset must NOT fire until STALE_EXECUTING_MS has elapsed, or it would yank
    // an in-flight row out from under a running execution.
    await withTenant(tenantId, async (tx) => {
      await tx.execute(sql`
        UPDATE remediation_proposals
        SET status = 'executing', executed_at = now() - interval '30 seconds', executor_kind = 'noop'
        WHERE id = ${proposalId}
      `);
    });

    await runRemediationExecutionOnce(new DevNoopExecutor());

    const row = await getProposal(tenantId, proposalId);
    // Still executing — neither recovered nor finalized by this sweep.
    expect(row.status).toBe("executing");
    expect(row.externalRef).toBeNull();
  });

  it("is a no-op when the executor is null (default-inert)", async () => {
    const tenantId = uniqueTenant("rem-exec-inert");
    const findingId = await createFinding(tenantId);
    const proposalId = await createConfirmedProposal(tenantId, findingId);

    const summary = await runRemediationExecutionOnce(null);
    expect(summary).toEqual({ executed: 0, failed: 0, tenants: 0 });

    const row = await getProposal(tenantId, proposalId);
    expect(row.status).toBe("confirmed");
  });
});
