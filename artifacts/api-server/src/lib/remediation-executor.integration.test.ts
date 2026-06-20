// Integration coverage for the DB-touching remediation executor backend
// (RedactionQueueExecutor). Hits the shared dev Postgres, so it follows the
// M1.9 isolation discipline (per-test tenant via uniqueTenant). Verifies:
//   - executing a redact_at_source action ENQUEUES a queued redaction_requests
//     row (the agent plane never deletes at source) and returns its id as the
//     external_ref idempotency anchor;
//   - a second execute() for the same proposal is idempotent (ON CONFLICT DO
//     NOTHING) — one row, same external_ref;
//   - RLS isolates redaction_requests per tenant.

import { describe, it, expect, beforeAll } from "vitest";
import { and, eq } from "drizzle-orm";
import { db, bootstrap, redactionRequestsTable } from "@workspace/db";
import { withTenant } from "./db-context";
import {
  RedactionQueueExecutor,
  type RemediationExecutionInput,
} from "./remediation-executor";
import { uniq, uniqueTenant } from "../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const input = (
  tenantId: string,
  over: Partial<RemediationExecutionInput> = {},
): RemediationExecutionInput => ({
  proposalId: `prop_${uniq()}`,
  tenantId,
  findingId: `F_${uniq()}`,
  actionType: "redact_at_source",
  summary: "Redact the leaked field at source",
  rationale: "Repeated PHI in this log group; redact at the source pipeline",
  ...over,
});

async function rowsFor(tenantId: string, proposalId: string) {
  return withTenant(tenantId, async (tx) =>
    tx
      .select()
      .from(redactionRequestsTable)
      .where(
        and(
          eq(redactionRequestsTable.tenantId, tenantId),
          eq(redactionRequestsTable.proposalId, proposalId),
        ),
      ),
  );
}

describe("RedactionQueueExecutor", () => {
  it("enqueues a queued request row and returns its id as external_ref", async () => {
    const tenantId = uniqueTenant("redq-enqueue");
    const ex = new RedactionQueueExecutor();
    const inp = input(tenantId);
    const result = await ex.execute(inp);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.externalRef).toMatch(/^redaction-queue:rq_/);

    const rows = await rowsFor(tenantId, inp.proposalId);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("queued");
    expect(rows[0].findingId).toBe(inp.findingId);
    expect(rows[0].actionType).toBe("redact_at_source");
    expect(result.externalRef).toBe(`redaction-queue:${rows[0].id}`);
  });

  it("is idempotent: a second execute() for the same proposal makes no new row", async () => {
    const tenantId = uniqueTenant("redq-idem");
    const ex = new RedactionQueueExecutor();
    const inp = input(tenantId);

    const first = await ex.execute(inp);
    const second = await ex.execute(inp);

    expect(first).toEqual(second);
    const rows = await rowsFor(tenantId, inp.proposalId);
    expect(rows).toHaveLength(1);
  });

  it("isolates rows per tenant under RLS", async () => {
    const tenantA = uniqueTenant("redq-rls-a");
    const tenantB = uniqueTenant("redq-rls-b");
    const ex = new RedactionQueueExecutor();
    const inpA = input(tenantA);
    await ex.execute(inpA);

    // Tenant B cannot see tenant A's request.
    const seenByB = await rowsFor(tenantB, inpA.proposalId);
    expect(seenByB).toHaveLength(0);
    const seenByA = await rowsFor(tenantA, inpA.proposalId);
    expect(seenByA).toHaveLength(1);
  });
});
