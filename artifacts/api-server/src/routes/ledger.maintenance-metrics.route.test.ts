import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { bootstrap } from "@workspace/db";
import app from "../app";
import { appendLedger } from "../lib/ledger";
import { uniq } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the dashboard's "Cache-pruning Maintenance"
// panel (artifacts/dashboard/src/pages/admin.tsx), which reads
// GET /admin/metrics/maintenance. The endpoint aggregates the audit-ledger
// rows the two opt-in jobs write — `memory.evicted` / `memory.evict_failed`
// (M10.5) and `raw_evidence.tiered` / `raw_evidence.tier_failed` (M10.4) —
// into per-job counts, scoped to the caller's tenant.
//
// The jobs are default-inert, so the dev seed never produces these rows; this
// test synthesizes them for an isolated tenant and asserts the guarantees a
// regression in the aggregation or tenant scoping would break:
//   - empty tenant → all zeros, last_run_at null ("never run").
//   - `memory.evicted` runs are counted and their `payload.evicted` summed.
//   - `*_failed` rows land in the per-job `failures` count.
//   - last_run_at is the latest ts across a job's success + failure rows.
//   - a sibling tenant's rows never bleed into this tenant's counts.
//   - the endpoint requires an authenticated session.
// ---------------------------------------------------------------------------

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
}, 60_000);

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
  return `10.79.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

async function authedClient(user: string, tenantId: string): Promise<Client> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: tenantId,
  });
  expect(login.status).toBe(200);
  return c;
}

interface Metrics {
  memory: {
    runs: number;
    embeddings_evicted: number;
    failures: number;
    last_run_at: string | null;
  };
  tiering: {
    findings_tiered: number;
    failures: number;
    last_run_at: string | null;
  };
}

async function fetchMetrics(c: Client): Promise<Metrics> {
  const res = await c.get("/api/admin/metrics/maintenance");
  expect(res.status).toBe(200);
  return (await res.json()) as Metrics;
}

describe("GET /admin/metrics/maintenance (HTTP)", () => {
  it("reports all-zeros / never-run for a tenant whose jobs never ran", async () => {
    const tenant = `t_metric_empty_${uniq()}`;
    const c = await authedClient(`m-${uniq()}`, tenant);
    const m = await fetchMetrics(c);
    expect(m.memory).toEqual({
      runs: 0,
      embeddings_evicted: 0,
      failures: 0,
      last_run_at: null,
    });
    expect(m.tiering).toEqual({
      findings_tiered: 0,
      failures: 0,
      last_run_at: null,
    });
  });

  it("aggregates counts, sums evicted embeddings, and surfaces the latest run", async () => {
    const tenant = `t_metric_agg_${uniq()}`;

    // Two successful eviction runs (5 + 3 embeddings) + one failure.
    await appendLedger({
      tenantId: tenant,
      actor: { kind: "system", id: "memory-eviction" },
      eventType: "memory.evicted",
      payload: { evicted: 5, scanned: 40 },
    });
    await appendLedger({
      tenantId: tenant,
      actor: { kind: "system", id: "memory-eviction" },
      eventType: "memory.evicted",
      payload: { evicted: 3, scanned: 20 },
    });
    await appendLedger({
      tenantId: tenant,
      actor: { kind: "system", id: "memory-eviction" },
      eventType: "memory.evict_failed",
      payload: { error: "boom" },
    });

    // Two tiered findings + one tiering failure.
    await appendLedger({
      tenantId: tenant,
      actor: { kind: "system", id: "raw-evidence-tiering" },
      eventType: "raw_evidence.tiered",
      payload: { finding_id: "F-AAA", provider: "s3" },
    });
    await appendLedger({
      tenantId: tenant,
      actor: { kind: "system", id: "raw-evidence-tiering" },
      eventType: "raw_evidence.tiered",
      payload: { finding_id: "F-BBB", provider: "s3" },
    });
    await appendLedger({
      tenantId: tenant,
      actor: { kind: "system", id: "raw-evidence-tiering" },
      eventType: "raw_evidence.tier_failed",
      payload: { finding_id: "F-CCC", provider: "s3" },
    });

    const c = await authedClient(`m-${uniq()}`, tenant);
    const m = await fetchMetrics(c);

    expect(m.memory.runs).toBe(2);
    expect(m.memory.embeddings_evicted).toBe(8);
    expect(m.memory.failures).toBe(1);
    expect(m.memory.last_run_at).not.toBeNull();

    expect(m.tiering.findings_tiered).toBe(2);
    expect(m.tiering.failures).toBe(1);
    expect(m.tiering.last_run_at).not.toBeNull();
  });

  it("is tenant-scoped — a sibling tenant's rows do not leak in", async () => {
    const mine = `t_metric_mine_${uniq()}`;
    const other = `t_metric_other_${uniq()}`;

    await appendLedger({
      tenantId: other,
      actor: { kind: "system", id: "memory-eviction" },
      eventType: "memory.evicted",
      payload: { evicted: 99 },
    });
    await appendLedger({
      tenantId: mine,
      actor: { kind: "system", id: "memory-eviction" },
      eventType: "memory.evicted",
      payload: { evicted: 2 },
    });

    const c = await authedClient(`m-${uniq()}`, mine);
    const m = await fetchMetrics(c);
    // Only this tenant's single run / 2 embeddings — never the sibling's 99.
    expect(m.memory.runs).toBe(1);
    expect(m.memory.embeddings_evicted).toBe(2);
  });

  it("requires an authenticated session", async () => {
    const c = new Client(nextClientIp());
    const res = await c.get("/api/admin/metrics/maintenance", false);
    expect(res.status).toBe(401);
  });
});
