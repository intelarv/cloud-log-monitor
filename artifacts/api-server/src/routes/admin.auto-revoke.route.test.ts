import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { and, desc, eq, gt, sql } from "drizzle-orm";
import {
  db,
  breakGlassGrantsTable,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for auto-revoking break-glass access when its
// finding is resolved (POST /admin/findings/:id/resolve).
//
// Guarantees asserted, over the real session + step-up cookie flow:
//   - Before resolution, an active grant authorizes the raw read (200).
//   - After the finding transitions to a closed state, the grant is no longer
//     active (revoked_at set, active=false) and the raw read fails closed
//     (403, break_glass_required) — exactly as if it had been manually revoked.
//   - The auto-revoke is ledgered `break_glass.revoked` with a distinct system
//     actor + reason "finding_resolved" + auto_revoked:true, so it is
//     distinguishable from an analyst/operator revoke.
//   - Re-resolving an already-resolved finding is idempotent (transitioned
//     false, no new revoke).
//
// A non-critical (high) finding is used so the grant is immediately active
// (the two-person approval path only applies to critical findings).
// ---------------------------------------------------------------------------

const TENANT = "default";
import { uniq, ledgerHeadSeq } from "../test-support/ledger-harness";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  await new Promise<void>((resolve) => {
    server = createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
  return async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
});

// Minimal cookie jar over fetch (fetch does not persist Set-Cookie itself).
// Each client presents a distinct source IP via X-Forwarded-For so the per-IP
// login/step-up rate limiters key on the client, not the shared loopback.
class Client {
  private jar = new Map<string, string>();

  constructor(private readonly ip: string) {}

  private cookieHeader(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  private absorb(res: Response): void {
    for (const raw of res.headers.getSetCookie()) {
      const pair = raw.split(";")[0]!;
      const eq = pair.indexOf("=");
      if (eq < 0) continue;
      this.jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }

  async post(path: string, body: unknown): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": this.ip,
        ...(this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
      body: JSON.stringify(body),
    });
    this.absorb(res);
    return res;
  }

  async get(path: string): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: {
        "x-forwarded-for": this.ip,
        ...(this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
    });
    this.absorb(res);
    return res;
  }
}

let ipCounter = 0;
function nextClientIp(): string {
  ipCounter += 1;
  return `10.40.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

async function authedClient(user: string): Promise<{ c: Client; sub: string }> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  const loginBody = (await login.json()) as { sub: string };
  const stepUp = await c.post("/api/auth/step-up", {
    token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
    reason: "route test auto-revoke on finding resolution",
  });
  expect(stepUp.status).toBe(200);
  return { c, sub: loginBody.sub };
}

/** Insert a HIGH-severity finding (so the grant is active immediately — no
 *  two-person approval), with an inline raw-evidence payload so the raw read
 *  can succeed while the grant is active. */
async function createHighFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      status: "open",
      source: `fixture:autorevoke:${uniq()}`,
      fingerprint: `phi:ssn:autorevoke:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Create an immediately-active grant on a non-critical finding via the route. */
async function createActiveGrant(
  requester: Client,
  findingId: string,
): Promise<string> {
  const grantRes = await requester.post("/api/admin/break-glass/grants", {
    finding_id: findingId,
    justification: "route test auto-revoke active grant",
    ttl_seconds: 600,
  });
  expect(grantRes.status).toBe(201);
  const grant = (await grantRes.json()) as {
    id: string;
    requires_second_approval: boolean;
    active: boolean;
  };
  expect(grant.requires_second_approval).toBe(false);
  expect(grant.active).toBe(true);
  return grant.id;
}


/** Inject an immediately-active grant DIRECTLY via the DB (no route), mirroring
 *  the task's "[DB] inject an active break-glass grant" setup. break_glass_grants
 *  is FORCE RLS, so the write goes through `withTenant` (sets the app.tenant_id
 *  GUC) — a plain `db` write would be filtered out by the row-level policy. */
async function injectActiveGrant(
  findingId: string,
  userId: string,
): Promise<string> {
  const id = `bg_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(breakGlassGrantsTable).values({
      id,
      tenantId: TENANT,
      userId,
      findingId,
      justification: "task104 db-injected active grant",
      expiresAt: new Date(Date.now() + 10 * 60_000),
      revokedAt: null,
      requiresSecondApproval: false,
    });
  });
  return id;
}

/** Read a grant's `revoked_at` straight from the DB (under tenant context, as
 *  RLS requires) so the close-out's revoke persistence is verified at the
 *  storage layer, not just through an API projection. */
async function readGrantRevokedAt(grantId: string): Promise<Date | null> {
  const rows = await withTenant(TENANT, async (tx) =>
    tx
      .select({ revokedAt: breakGlassGrantsTable.revokedAt })
      .from(breakGlassGrantsTable)
      .where(
        and(
          eq(breakGlassGrantsTable.id, grantId),
          eq(breakGlassGrantsTable.tenantId, TENANT),
        ),
      )
      .limit(1),
  );
  return rows[0]?.revokedAt ?? null;
}

/** Delete the injected finding + grant rows (tenant GUC via `withTenant`).
 *  Never touches the append-only `ledger_entries` table. */
async function cleanupInjected(findingId: string, grantId: string): Promise<void> {
  await withTenant(TENANT, async (tx) => {
    await tx
      .delete(breakGlassGrantsTable)
      .where(
        and(
          eq(breakGlassGrantsTable.id, grantId),
          eq(breakGlassGrantsTable.tenantId, TENANT),
        ),
      );
    await tx
      .delete(findingsTable)
      .where(
        and(
          eq(findingsTable.id, findingId),
          eq(findingsTable.tenantId, TENANT),
        ),
      );
  });
}

/** The most-recent ledger entry of `eventType` for `findingId` after `sinceSeq`. */
async function latestLedgerEvent(
  eventType: string,
  findingId: string,
  sinceSeq: number,
): Promise<
  | {
      actor: { kind: string; id: string };
      payload: Record<string, unknown>;
    }
  | undefined
> {
  const rows = await db
    .select({
      actor: ledgerEntriesTable.actor,
      payload: ledgerEntriesTable.payload,
    })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, eventType),
        eq(ledgerEntriesTable.subjectId, findingId),
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  const row = rows[0];
  if (!row) return undefined;
  return {
    actor: row.actor as { kind: string; id: string },
    payload: row.payload as Record<string, unknown>,
  };
}

async function fetchGrant(
  client: Client,
  grantId: string,
): Promise<{ active: boolean; revoked_at: string | null } | undefined> {
  const res = await client.get("/api/admin/break-glass/grants");
  expect(res.status).toBe(200);
  const grants = (await res.json()) as Array<{
    id: string;
    active: boolean;
    revoked_at: string | null;
  }>;
  return grants.find((g) => g.id === grantId);
}

describe("auto-revoke break-glass on finding resolution (HTTP)", () => {
  it("resolving a finding revokes its active grant and fails the raw read closed", async () => {
    const findingId = await createHighFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);
    const grantId = await createActiveGrant(requester, findingId);

    // While the grant is active, the raw read succeeds (200).
    const readOk = await requester.get(`/api/admin/findings/${findingId}/raw`);
    expect(readOk.status).toBe(200);

    // Resolve the finding.
    const before = await ledgerHeadSeq();
    const resolve = await requester.post(
      `/api/admin/findings/${findingId}/resolve`,
      { status: "resolved" },
    );
    expect(resolve.status).toBe(200);
    const resolveBody = (await resolve.json()) as {
      transitioned: boolean;
      revoked_grants: number;
    };
    expect(resolveBody.transitioned).toBe(true);
    expect(resolveBody.revoked_grants).toBe(1);

    // The grant is no longer active and carries a revoked_at.
    const grant = await fetchGrant(requester, grantId);
    expect(grant).toBeDefined();
    expect(grant!.active).toBe(false);
    expect(grant!.revoked_at).not.toBeNull();

    // The auto-revoke is ledgered with a distinct system actor + reason.
    const revoked = await latestLedgerEvent(
      "break_glass.revoked",
      findingId,
      before,
    );
    expect(revoked).toBeDefined();
    expect(revoked!.actor.kind).toBe("system");
    expect(revoked!.actor.id).toBe("finding-resolver");
    expect(revoked!.payload["reason"]).toBe("finding_resolved");
    expect(revoked!.payload["auto_revoked"]).toBe(true);
    expect(revoked!.payload["grant_id"]).toBe(grantId);

    // The resolution itself is ledgered too (finding lifecycle).
    const resolved = await latestLedgerEvent(
      "finding.resolved",
      findingId,
      before,
    );
    expect(resolved).toBeDefined();
    expect(resolved!.payload["status"]).toBe("resolved");

    // The raw read now fails closed — the revoked grant is filtered out of the
    // lookup, so the route reports "no active grant".
    const readBefore = await ledgerHeadSeq();
    const readClosed = await requester.get(
      `/api/admin/findings/${findingId}/raw`,
    );
    expect(readClosed.status).toBe(403);
    const closedBody = (await readClosed.json()) as {
      break_glass_required?: boolean;
    };
    expect(closedBody.break_glass_required).toBe(true);
    // No raw access disclosed, so nothing was ledgered for the blocked read.
    const accessed = await latestLedgerEvent(
      "break_glass.raw_phi_accessed",
      findingId,
      readBefore,
    );
    expect(accessed).toBeUndefined();
  });

  // Task #104: the security-relevant variant — closing out a finding that has a
  // SINGLE active break-glass grant must END that emergency access. This drives
  // the real login -> close-out HTTP flow against a finding + grant injected
  // directly via the DB ([DB] setup), verifies revoke persistence by reading
  // break_glass_grants straight from the DB (active -> revoked), and cleans up
  // the injected rows afterwards (tenant GUC via withTenant; never deletes from
  // the append-only ledger). The toast wording the analyst sees for this exact
  // single-grant case is covered by the dashboard component test
  // (resolve-finding-modal.test.tsx), and a live browser run by the Playwright
  // testing subagent.
  it("closing out a finding ends its single active emergency-access grant (DB-verified lifecycle + cleanup)", async () => {
    const findingId = await createHighFinding();
    const { c: requester, sub } = await authedClient(`req-${uniq()}`);
    const grantId = await injectActiveGrant(findingId, sub);

    try {
      // Active before close-out: the grant has no revoked_at in the DB.
      expect(await readGrantRevokedAt(grantId)).toBeNull();

      // Close out (resolve) the finding over the real HTTP route.
      const resolve = await requester.post(
        `/api/admin/findings/${findingId}/resolve`,
        { status: "resolved" },
      );
      expect(resolve.status).toBe(200);
      const body = (await resolve.json()) as {
        transitioned: boolean;
        revoked_grants: number;
      };
      expect(body.transitioned).toBe(true);
      // Exactly the one injected grant was auto-revoked (drives the singular
      // "1 active emergency-access grant was automatically revoked." toast).
      expect(body.revoked_grants).toBe(1);

      // Revoked after close-out: the DB row now carries a revoked_at, proving
      // the emergency access actually ended at the storage layer.
      const revokedAt = await readGrantRevokedAt(grantId);
      expect(revokedAt).not.toBeNull();
    } finally {
      await cleanupInjected(findingId, grantId);
    }

    // Cleanup actually removed the injected grant + finding rows.
    expect(await readGrantRevokedAt(grantId)).toBeNull();
  });

  it("re-resolving an already-resolved finding is an idempotent no-op", async () => {
    const findingId = await createHighFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);
    await createActiveGrant(requester, findingId);

    const first = await requester.post(
      `/api/admin/findings/${findingId}/resolve`,
      { status: "resolved" },
    );
    expect(first.status).toBe(200);
    expect(((await first.json()) as { revoked_grants: number }).revoked_grants).toBe(
      1,
    );

    // Second resolve to the same state: no transition, no further revoke, and
    // no new finding.resolved ledger entry.
    const before = await ledgerHeadSeq();
    const second = await requester.post(
      `/api/admin/findings/${findingId}/resolve`,
      { status: "resolved" },
    );
    expect(second.status).toBe(200);
    const secondBody = (await second.json()) as {
      transitioned: boolean;
      revoked_grants: number;
    };
    expect(secondBody.transitioned).toBe(false);
    expect(secondBody.revoked_grants).toBe(0);
    expect(
      await latestLedgerEvent("finding.resolved", findingId, before),
    ).toBeUndefined();
  });

  it("resolving an unknown finding returns 404", async () => {
    const { c } = await authedClient(`req-${uniq()}`);
    const res = await c.post(
      `/api/admin/findings/does-not-exist-${uniq()}/resolve`,
      { status: "resolved" },
    );
    expect(res.status).toBe(404);
  });
});
