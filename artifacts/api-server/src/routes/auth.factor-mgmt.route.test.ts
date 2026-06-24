import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { bootstrap } from "@workspace/db";
import app from "../app";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the M29 backup-code / factor-management
// endpoints under the DEFAULT `dev` step-up provider. The dev provider has no
// enrollable second factor (it uses a shared token), so every factor-management
// route MUST 404 — this is the wiring that keeps the credential-free dev /
// eval-gate surface byte-identical. The happy-path (totp/webauthn/oidc) consume
// + generate behaviour is covered by recovery-codes.integration.test.ts.
//
// Drives the real Express app over HTTP with a minimal cookie jar so the
// session gate is satisfied before the provider 404 check is reached.
// ---------------------------------------------------------------------------

const TENANT = "default";

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

let ipCounter = 0;
function nextClientIp(): string {
  ipCounter += 1;
  return `10.30.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

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

/** A session-authed (but not step-up) client. */
async function sessionClient(): Promise<Client> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: "analyst-fm",
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  return c;
}

describe("factor-management routes under the dev step-up provider", () => {
  it("404s recovery status (session present, provider=dev)", async () => {
    const c = await sessionClient();
    const res = await c.get("/api/auth/step-up/recovery/status");
    expect(res.status).toBe(404);
  });

  it("404s recovery generate after a dev step-up", async () => {
    const c = await sessionClient();
    const stepUp = await c.post("/api/auth/step-up", {
      token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
      reason: "route test factor mgmt",
    });
    expect(stepUp.status).toBe(200);
    const res = await c.post("/api/auth/step-up/recovery/generate", {});
    expect(res.status).toBe(404);
  });

  it("404s recovery consume", async () => {
    const c = await sessionClient();
    const res = await c.post("/api/auth/step-up/recovery", {
      token: "AAAA-BBBB",
      reason: "route test factor mgmt",
    });
    expect(res.status).toBe(404);
  });

  it("404s factor remove after a dev step-up", async () => {
    const c = await sessionClient();
    const stepUp = await c.post("/api/auth/step-up", {
      token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
      reason: "route test factor mgmt",
    });
    expect(stepUp.status).toBe(200);
    const res = await c.post("/api/auth/step-up/factor/remove", {});
    expect(res.status).toBe(404);
  });

  it("requires a session before reaching the provider check", async () => {
    const c = new Client(nextClientIp());
    const res = await c.get("/api/auth/step-up/recovery/status");
    expect(res.status).toBe(401);
  });
});
