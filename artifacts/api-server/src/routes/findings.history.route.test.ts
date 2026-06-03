import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { eq } from "drizzle-orm";
import { findingsTable, bootstrap } from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the finding-scoped audit history endpoint
// (GET /findings/:id/history) that backs the dashboard's inline lifecycle
// timeline.
//
// Guarantees asserted, over the real session cookie flow:
//   - Returns the finding's ledger events (finding.resolved / finding.reopened)
//     most-recent-first, including the free-text reopen reason in the payload.
//   - Each entry carries actor + timestamp.
//   - Only events for the requested finding are returned (subject scoping).
//   - Unauthenticated requests are refused (401).
// ---------------------------------------------------------------------------

const TENANT = "default";
const uniq = () => Math.random().toString(36).slice(2, 10);

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

  async get(path: string, withCookie = true): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: {
        "x-forwarded-for": this.ip,
        ...(withCookie && this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
    });
    this.absorb(res);
    return res;
  }
}

let ipCounter = 0;
function nextClientIp(): string {
  ipCounter += 1;
  return `10.42.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

async function authedClient(user: string): Promise<{ c: Client; sub: string }> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  const loginBody = (await login.json()) as { sub: string };
  return { c, sub: loginBody.sub };
}

async function createOpenFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      status: "open",
      source: `fixture:history:${uniq()}`,
      fingerprint: `phi:ssn:history:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

type HistoryEntry = {
  seq: number;
  ts: string;
  event_type: string;
  actor: { kind: string; id: string };
  subject_id: string;
  payload: Record<string, unknown>;
};

describe("finding history (HTTP)", () => {
  it("returns resolve + reopen events most-recent-first with reason, actor and timestamp", async () => {
    const findingId = await createOpenFinding();
    const { c, sub } = await authedClient(`hist-${uniq()}`);

    const resolve = await c.post(`/api/admin/findings/${findingId}/resolve`, {
      status: "resolved",
    });
    expect(resolve.status).toBe(200);

    const reason = "Closed by mistake during triage; still under investigation.";
    const reopen = await c.post(`/api/admin/findings/${findingId}/reopen`, {
      reason,
    });
    expect(reopen.status).toBe(200);

    const res = await c.get(`/api/findings/${findingId}/history`);
    expect(res.status).toBe(200);
    const events = (await res.json()) as HistoryEntry[];

    // Every returned event belongs to this finding.
    for (const ev of events) {
      expect(ev.subject_id).toBe(findingId);
      expect(typeof ev.ts).toBe("string");
      expect(ev.actor).toBeDefined();
    }

    // Most-recent-first: the reopen (later) precedes the resolve (earlier).
    const reopenIdx = events.findIndex((e) => e.event_type === "finding.reopened");
    const resolveIdx = events.findIndex((e) => e.event_type === "finding.resolved");
    expect(reopenIdx).toBeGreaterThanOrEqual(0);
    expect(resolveIdx).toBeGreaterThanOrEqual(0);
    expect(reopenIdx).toBeLessThan(resolveIdx);

    // The reopen carries the free-text reason and the human actor.
    const reopened = events[reopenIdx]!;
    expect(reopened.payload["reason"]).toBe(reason);
    expect(reopened.actor.kind).toBe("human");
    expect(reopened.actor.id).toBe(sub);
  });

  it("scopes events to the requested finding only", async () => {
    const a = await createOpenFinding();
    const b = await createOpenFinding();
    const { c } = await authedClient(`hist-${uniq()}`);

    await c.post(`/api/admin/findings/${a}/resolve`, { status: "resolved" });
    await c.post(`/api/admin/findings/${a}/reopen`, {
      reason: "first finding reopen",
    });
    await c.post(`/api/admin/findings/${b}/resolve`, { status: "resolved" });

    const res = await c.get(`/api/findings/${a}/history`);
    expect(res.status).toBe(200);
    const events = (await res.json()) as HistoryEntry[];
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((e) => e.subject_id === a)).toBe(true);
  });

  it("requires an authenticated session", async () => {
    const findingId = await createOpenFinding();
    const c = new Client(nextClientIp());
    const res = await c.get(`/api/findings/${findingId}/history`, false);
    expect(res.status).toBe(401);
  });
});
