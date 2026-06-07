import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { bootstrap } from "@workspace/db";
import app from "../app";
import { appendLedger } from "../lib/ledger";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the dashboard's paged "Audit Ledger" view
// (artifacts/dashboard/src/pages/ledger.tsx), which loads activity page-by-page
// via the GET /ledger `after_seq` cursor (100 at a time), accumulates pages
// client-side with a "Load newer entries" button, and shows an "End of history"
// indicator on the final short page.
//
// The dev seed only creates a handful of entries, so the multi-page path and
// the end-of-history transition are never exercised. This test seeds >200
// entries for one tenant/actor and replicates the dashboard's exact pagination
// loop against the REAL Express app, asserting the guarantees a regression in
// the cursor / accumulation logic would break:
//   - First page fills (PAGE_SIZE rows); subsequent pages append.
//   - The exclusive `after_seq` cursor never returns a row twice (no dups).
//   - Pages are strictly forward (each page's seqs are all > the previous).
//   - The final page is short (< PAGE_SIZE) → "End of history".
//   - The `?actor=` filter narrows the trail to one human actor across pages.
//   - A deep-link `?seq=` target loads inside the first (widened) page and
//     pagination still runs to the end without duplicates.
//   - A deep-link to a non-existent seq loads nothing (the "targetMissing"
//     notice path) instead of silently paging the whole tenant.
// ---------------------------------------------------------------------------

import { uniq } from "../test-support/ledger-harness";

// Mirror the dashboard's page size (artifacts/dashboard/src/pages/ledger.tsx).
const PAGE_SIZE = 100;

// A unique tenant per run so this test owns its entire ledger slice — the
// shared dev ledger is polluted by other test files (replit.md "Gotchas"), but
// GET /ledger is tenant-scoped, so a fresh tenant gives us an exact, isolated
// count to assert pagination against.
const TENANT = `t_pag_${uniq()}`;

// One human actor owns most of the trail (the ">200 entries for one actor"
// requirement); a second human + a system actor exist so the `?actor=` filter
// has something to actually filter out.
const ALICE = `alice-${uniq()}`;
const ALICE_COUNT = 215; // 3 actor-filtered pages: 100 + 100 + 15
const CAROL = `carol-${uniq()}`;
const CAROL_COUNT = 12;
const SYSTEM_COUNT = 3;
const TOTAL = ALICE_COUNT + CAROL_COUNT + SYSTEM_COUNT; // 230 → 100 + 100 + 30

let server: Server;
let baseUrl: string;
let aliceSeqs: number[] = [];

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

  // Seed the tenant's trail. Use a non-alertable marker event type so the
  // post-commit alert / supervisor / channel hooks stay inert. appendLedger
  // keeps the global hash chain valid and returns the assigned seq.
  for (let i = 0; i < ALICE_COUNT; i++) {
    const row = await appendLedger({
      tenantId: TENANT,
      actor: { kind: "human", id: ALICE, display_name: "Alice Analyst" },
      eventType: "system.pagination_test_marker",
      payload: { i, actor: "alice" },
    });
    aliceSeqs.push(row.seq);
  }
  for (let i = 0; i < CAROL_COUNT; i++) {
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "human", id: CAROL, display_name: "Carol Analyst" },
      eventType: "system.pagination_test_marker",
      payload: { i, actor: "carol" },
    });
  }
  for (let i = 0; i < SYSTEM_COUNT; i++) {
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "sys" },
      eventType: "system.pagination_test_marker",
      payload: { i, actor: "system" },
    });
  }

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
  return `10.77.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
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

interface Entry {
  seq: number;
  ts: string;
  tenant_id: string;
  actor: { kind: string; id: string; display_name?: string };
  event_type: string;
}

async function fetchPage(
  c: Client,
  cursor: number,
  actor?: string,
): Promise<Entry[]> {
  const params = new URLSearchParams();
  params.set("limit", String(PAGE_SIZE));
  params.set("after_seq", String(cursor));
  if (actor) params.set("actor", actor);
  const res = await c.get(`/api/ledger?${params.toString()}`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { entries: Entry[] };
  return body.entries;
}

// Faithfully replicate the dashboard's accumulate → dedup → reachedEnd loop:
//   - baseCursor: actor pivot starts at 0; a deep-link target widens the first
//     window to (targetSeq - 26); otherwise start at 0.
//   - each "Load newer entries" click advances the cursor to the last (highest)
//     accumulated seq; a page shorter than PAGE_SIZE means end of history.
async function paginateLikeDashboard(
  c: Client,
  opts: { actor?: string; targetSeq?: number } = {},
): Promise<{
  accumulated: Entry[];
  pages: Entry[][];
  duplicates: number;
  reachedEnd: boolean;
}> {
  const baseCursor = opts.actor
    ? 0
    : opts.targetSeq != null
      ? Math.max(0, opts.targetSeq - 26)
      : 0;
  let cursor = baseCursor;
  const accumulated: Entry[] = [];
  const seen = new Set<number>();
  const pages: Entry[][] = [];
  let duplicates = 0;
  let reachedEnd = false;

  while (!reachedEnd) {
    const page = await fetchPage(c, cursor, opts.actor);
    pages.push(page);
    for (const e of page) {
      if (seen.has(e.seq)) {
        duplicates++;
        continue;
      }
      seen.add(e.seq);
      accumulated.push(e);
    }
    reachedEnd = page.length < PAGE_SIZE;
    if (!reachedEnd) {
      accumulated.sort((a, b) => a.seq - b.seq);
      cursor = accumulated[accumulated.length - 1]!.seq;
    }
    if (pages.length > 50) throw new Error("runaway pagination guard tripped");
  }
  accumulated.sort((a, b) => a.seq - b.seq);
  return { accumulated, pages, duplicates, reachedEnd };
}

function assertStrictlyForwardPages(pages: Entry[][]): void {
  let prevMax = -Infinity;
  for (const page of pages) {
    for (const e of page) {
      expect(e.seq).toBeGreaterThan(prevMax);
      prevMax = e.seq;
    }
  }
}

describe("ledger pagination over hundreds of entries (HTTP)", () => {
  it("pages the full tenant trail, appends without dups, ends on a short page", async () => {
    const c = await authedClient(`pag-${uniq()}`, TENANT);
    const { accumulated, pages, duplicates, reachedEnd } =
      await paginateLikeDashboard(c);

    // Every tenant entry surfaced exactly once.
    expect(accumulated).toHaveLength(TOTAL);
    expect(duplicates).toBe(0);
    expect(reachedEnd).toBe(true);
    expect(new Set(accumulated.map((e) => e.seq)).size).toBe(TOTAL);
    expect(accumulated.every((e) => e.tenant_id === TENANT)).toBe(true);

    // Multi-page: first pages fill, the last page is short (End of history).
    expect(pages.length).toBe(Math.ceil(TOTAL / PAGE_SIZE));
    expect(pages[0]!.length).toBe(PAGE_SIZE);
    expect(pages[pages.length - 1]!.length).toBe(TOTAL % PAGE_SIZE);
    expect(pages[pages.length - 1]!.length).toBeLessThan(PAGE_SIZE);

    // Cursor is exclusive + strictly forward — the property a regression breaks.
    assertStrictlyForwardPages(pages);
  });

  it("the ?actor filter narrows pagination to one actor's full history", async () => {
    const c = await authedClient(`pag-${uniq()}`, TENANT);
    const { accumulated, pages, duplicates, reachedEnd } =
      await paginateLikeDashboard(c, { actor: ALICE });

    expect(accumulated).toHaveLength(ALICE_COUNT);
    expect(duplicates).toBe(0);
    expect(reachedEnd).toBe(true);
    // Only Alice's human-actor rows — never Carol's or the system rows.
    expect(
      accumulated.every((e) => e.actor.kind === "human" && e.actor.id === ALICE),
    ).toBe(true);

    expect(pages.length).toBe(Math.ceil(ALICE_COUNT / PAGE_SIZE));
    expect(pages[0]!.length).toBe(PAGE_SIZE);
    expect(pages[pages.length - 1]!.length).toBe(ALICE_COUNT % PAGE_SIZE);
    assertStrictlyForwardPages(pages);
  });

  it("a deep-link ?seq target loads in the first window and paging runs to the end", async () => {
    // A target well past the first default page (≈ the 160th of Alice's rows).
    const targetSeq = aliceSeqs[159]!;
    const c = await authedClient(`pag-${uniq()}`, TENANT);
    const { accumulated, pages, duplicates, reachedEnd } =
      await paginateLikeDashboard(c, { targetSeq });

    // The widened first window (after_seq = targetSeq - 26) brings the target
    // into the very first page, so the dashboard never shows "targetMissing".
    expect(pages[0]!.some((e) => e.seq === targetSeq)).toBe(true);
    // Target present exactly once across the accumulated, deduped trail.
    expect(accumulated.filter((e) => e.seq === targetSeq)).toHaveLength(1);
    expect(duplicates).toBe(0);
    expect(reachedEnd).toBe(true);
    assertStrictlyForwardPages(pages);
  });

  it("a deep-link to a non-existent seq loads nothing (targetMissing path)", async () => {
    const c = await authedClient(`pag-${uniq()}`, TENANT);
    // Far beyond the tenant head: the widened window starts past every row.
    const targetSeq = 999_999_999;
    const { accumulated, reachedEnd } = await paginateLikeDashboard(c, {
      targetSeq,
    });
    expect(reachedEnd).toBe(true);
    expect(accumulated.some((e) => e.seq === targetSeq)).toBe(false);
    expect(accumulated).toHaveLength(0);
  });

  it("requires an authenticated session", async () => {
    const c = new Client(nextClientIp());
    const res = await c.get("/api/ledger?limit=100&after_seq=0", false);
    expect(res.status).toBe(401);
  });
});
