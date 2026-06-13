import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { and, desc, eq, gt } from "drizzle-orm";
import {
  db,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";
import { proposeRemediationTool } from "../lib/tools";
import { uniq, ledgerHeadSeq, uniqueTenant } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the HITL remediation plane:
//   - propose_remediation tool writes a PENDING proposal + ledgers
//     `remediation.proposed` (agent actor) and never executes.
//   - GET    /api/admin/remediation/proposals  — list (session only)
//   - POST   /api/admin/remediation/proposals/:id/confirm — session + step-up,
//     CAS pending→confirmed, ledgers `remediation.confirmed`.
//   - POST   /api/admin/remediation/proposals/:id/reject  — session only,
//     CAS pending→rejected, ledgers `remediation.rejected`.
//
// One shared authed client for the whole file (step-up is per-IP rate limited
// 5/min, mirroring admin.raw-evidence.route.test.ts).
// ---------------------------------------------------------------------------

const TENANT = "default";

let server: Server;
let baseUrl: string;
let client: Client;

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
  client = await authedClient(`req-${uniq()}`);
  return async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
});

class Client {
  private jar = new Map<string, string>();
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
        ...(this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
      body: JSON.stringify(body),
    });
    this.absorb(res);
    return res;
  }
  async get(path: string): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: this.jar.size ? { cookie: this.cookieHeader() } : {},
    });
    this.absorb(res);
    return res;
  }
}

/** Login only (no step-up). */
async function sessionClient(user: string): Promise<Client> {
  const c = new Client();
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  return c;
}

/** Login + step-up so the client carries both cookies. */
async function authedClient(user: string): Promise<Client> {
  const c = await sessionClient(user);
  const stepUp = await c.post("/api/auth/step-up", {
    token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
    reason: "route test remediation confirm",
  });
  expect(stepUp.status).toBe(200);
  return c;
}

/** Insert a finding directly; returns its id. */
async function createFinding(tenantId = TENANT): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(tenantId, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      source: `fixture:remediation:${uniq()}`,
      fingerprint: `phi:ssn:remediation:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Drive the propose_remediation tool handler directly (mirrors what the chat
 *  agent does after policy revalidation). Returns the proposal id. */
async function propose(
  tenantId: string,
  findingId: string,
  userId = "agent-driver",
): Promise<string> {
  const out = await proposeRemediationTool.handler(
    {
      finding_id: findingId,
      action_type: "notify_owner",
      summary: "Notify the billing service owner",
      rationale: "Repeated PHI in this log group; owner should rotate retention",
    },
    {
      tenantId,
      userId,
      agent: "chat",
      onPolicyViolation: async () => {},
    },
  );
  expect(out.status).toBe("pending");
  return out.proposal_id;
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

describe("HITL remediation plane", () => {
  it("propose_remediation creates a pending proposal + ledgers remediation.proposed", async () => {
    const findingId = await createFinding();
    const before = await ledgerHeadSeq();
    const proposalId = await propose(TENANT, findingId);
    expect(proposalId).toMatch(/^rp_/);
    expect(await ledgerExists("remediation.proposed", findingId, before)).toBe(
      true,
    );

    // It must appear in the list, in pending state.
    const list = await client.get("/api/admin/remediation/proposals?status=pending");
    expect(list.status).toBe(200);
    const items = (await list.json()) as Array<Record<string, unknown>>;
    const mine = items.find((p) => p.id === proposalId);
    expect(mine).toBeDefined();
    expect(mine!.status).toBe("pending");
    expect(mine!.action_type).toBe("notify_owner");
  });

  it("propose_remediation refuses a finding that does not exist", async () => {
    await expect(propose(TENANT, "f_does_not_exist_xyz")).rejects.toThrow(
      /not found/,
    );
  });

  it("confirm requires step-up (session-only is refused)", async () => {
    const findingId = await createFinding();
    const proposalId = await propose(TENANT, findingId);
    const sessionOnly = await sessionClient(`req-${uniq()}`);
    const res = await sessionOnly.post(
      `/api/admin/remediation/proposals/${proposalId}/confirm`,
      {},
    );
    expect(res.status).toBe(401);
  });

  it("confirm (session + step-up) flips to confirmed + ledgers remediation.confirmed", async () => {
    const findingId = await createFinding();
    const proposalId = await propose(TENANT, findingId);
    const before = await ledgerHeadSeq();
    const res = await client.post(
      `/api/admin/remediation/proposals/${proposalId}/confirm`,
      { note: "approved after review" },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("confirmed");
    expect(body.decided_by_user_id).toBeTruthy();
    expect(await ledgerExists("remediation.confirmed", findingId, before)).toBe(
      true,
    );
  });

  it("confirm is idempotent under CAS — second confirm returns 409", async () => {
    const findingId = await createFinding();
    const proposalId = await propose(TENANT, findingId);
    const first = await client.post(
      `/api/admin/remediation/proposals/${proposalId}/confirm`,
      {},
    );
    expect(first.status).toBe(200);
    const second = await client.post(
      `/api/admin/remediation/proposals/${proposalId}/confirm`,
      {},
    );
    expect(second.status).toBe(409);
  });

  it("reject (session only) flips to rejected + ledgers remediation.rejected", async () => {
    const findingId = await createFinding();
    const proposalId = await propose(TENANT, findingId);
    const before = await ledgerHeadSeq();
    const sessionOnly = await sessionClient(`req-${uniq()}`);
    const res = await sessionOnly.post(
      `/api/admin/remediation/proposals/${proposalId}/reject`,
      { note: "not warranted" },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("rejected");
    expect(await ledgerExists("remediation.rejected", findingId, before)).toBe(
      true,
    );
  });

  it("reject after confirm returns 409 (terminal state)", async () => {
    const findingId = await createFinding();
    const proposalId = await propose(TENANT, findingId);
    const confirm = await client.post(
      `/api/admin/remediation/proposals/${proposalId}/confirm`,
      {},
    );
    expect(confirm.status).toBe(200);
    const sessionOnly = await sessionClient(`req-${uniq()}`);
    const reject = await sessionOnly.post(
      `/api/admin/remediation/proposals/${proposalId}/reject`,
      {},
    );
    expect(reject.status).toBe(409);
  });

  it("confirm of a non-existent proposal returns 404", async () => {
    const res = await client.post(
      "/api/admin/remediation/proposals/rp_nope_xyz/confirm",
      {},
    );
    expect(res.status).toBe(404);
  });

  it("a confirm note carrying PHI is rejected by content policy (400)", async () => {
    const findingId = await createFinding();
    const proposalId = await propose(TENANT, findingId);
    const res = await client.post(
      `/api/admin/remediation/proposals/${proposalId}/confirm`,
      { note: "patient 123-45-6789 approved" },
    );
    expect(res.status).toBe(400);
    // The proposal must remain pending (not consumed by the rejected attempt).
    const list = await client.get(
      "/api/admin/remediation/proposals?status=pending",
    );
    const items = (await list.json()) as Array<Record<string, unknown>>;
    expect(items.find((p) => p.id === proposalId)?.status).toBe("pending");
  });

  it("proposals are tenant-scoped (RLS): another tenant cannot see them", async () => {
    const otherTenant = uniqueTenant("remediation-iso");
    const findingId = await createFinding(otherTenant);
    const proposalId = await propose(otherTenant, findingId);
    // The default-tenant client must NOT see the other tenant's proposal.
    const list = await client.get("/api/admin/remediation/proposals");
    const items = (await list.json()) as Array<Record<string, unknown>>;
    expect(items.find((p) => p.id === proposalId)).toBeUndefined();
  });
});
