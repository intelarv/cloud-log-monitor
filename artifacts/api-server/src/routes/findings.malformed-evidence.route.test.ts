import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { bootstrap, findingsTable } from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// Regression: a single finding with a partial/malformed `redacted_evidence`
// record must not 500 the whole findings list.
//
// Findings created via the ingest/replay path historically could land with an
// evidence blob missing required fields (e.g. `truncated`). The list endpoint
// validates every row with the API schema, so one bad row used to throw and
// take down GET /api/findings entirely — hiding every finding from analysts.
//
// This test inserts a finding whose stored `redacted_evidence` is missing the
// required `truncated` flag (and `redactions`), then drives the real Express
// app over HTTP and asserts the list still returns 200 AND still contains that
// finding with a sensible normalized fallback.
// ---------------------------------------------------------------------------

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

async function authedClient(user: string, tenantId: string): Promise<Client> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: tenantId,
  });
  expect(login.status).toBe(200);
  return c;
}

describe("findings list tolerates malformed redacted_evidence (HTTP)", () => {
  it("returns 200 and includes a finding whose evidence is missing required fields", async () => {
    const tenant = `t_malformed_${uniq()}`;
    const client = await authedClient(`analyst-${uniq()}`, tenant);

    const goodId = `f_good_${uniq()}`;
    const badId = `f_bad_${uniq()}`;

    await withTenant(tenant, async (tx) => {
      await tx.insert(findingsTable).values({
        id: goodId,
        tenantId: tenant,
        classification: "phi",
        subclass: "ssn",
        severity: "high",
        source: `fixture:malformed:${uniq()}`,
        fingerprint: `phi:ssn:malformed-good:${uniq()}:v1`,
        redactedEvidence: {
          snippet: "x=[REDACTED:ssn]",
          redactions: ["ssn"],
          truncated: false,
          trust: "untrusted",
        },
        rawEvidence: null,
        rawEvidenceRef: null,
        detectorVersion: "stage1@test",
      });
      // Intentionally partial evidence: missing `truncated` and `redactions`.
      // Cast through unknown because the column's TS type requires the full
      // shape — we're simulating an older ingest row that bypassed it.
      await tx.insert(findingsTable).values({
        id: badId,
        tenantId: tenant,
        classification: "phi",
        subclass: "ssn",
        severity: "high",
        source: `fixture:malformed:${uniq()}`,
        fingerprint: `phi:ssn:malformed-bad:${uniq()}:v1`,
        redactedEvidence: { snippet: "y=[REDACTED:ssn]" } as unknown as {
          snippet: string;
          redactions: string[];
          truncated: boolean;
          trust: "trusted" | "untrusted";
        },
        rawEvidence: null,
        rawEvidenceRef: null,
        detectorVersion: "stage1@test",
      });
    });

    const res = await client.get("/api/findings?severity=high");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<{
      id: string;
      redacted_evidence: { snippet: string; redactions: string[]; truncated: boolean };
    }>;

    const good = rows.find((r) => r.id === goodId);
    const bad = rows.find((r) => r.id === badId);

    // The healthy row is present and intact.
    expect(good).toBeDefined();
    // The malformed row still shows up with a normalized fallback.
    expect(bad).toBeDefined();
    expect(bad!.redacted_evidence.truncated).toBe(false);
    expect(bad!.redacted_evidence.redactions).toEqual([]);
    expect(bad!.redacted_evidence.snippet).toBe("y=[REDACTED:ssn]");
  });
});
