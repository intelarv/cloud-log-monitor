import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { sql } from "drizzle-orm";
import { bootstrap } from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";
import { initEmbedderFromEnv } from "../lib/embedder-config";
import { initSearchProviderFromEnv } from "../lib/search-config";
import { uniq } from "../test-support/ledger-harness";
import * as chatRecall from "../lib/chat-recall";
import {
  __setLlmRuntimeForTest,
  __resetLlmRuntimeForTest,
  type LlmAgentRuntime,
  type LlmGenerateOpts,
  type LlmGenerateResult,
} from "../lib/llm-runtime";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for M19 semantic memory recall, exercising the
// chat POST turn end-to-end through the AG-UI SSE stream. Two invariants:
//   1. Switch OFF (default) => byte-identical to M18: a turn writes NO
//      chat_message_embeddings rows and runs no recall query.
//   2. Switch ON => each persisted message is embedded (user + assistant), a
//      follow-up turn recalls over them, and a fresh session with nothing to
//      recall yet falls back to the recency window so the turn still succeeds.
//
// Credential-free: the LLM is a scripted in-process runtime (no provider call)
// and the embedder is the offline FeatureHashEmbedder seated by bootstrap().
// ---------------------------------------------------------------------------

const TENANT = "default";
const RECALL_ENV = "CHAT_MEMORY_SEMANTIC_RECALL";

let server: Server;
let baseUrl: string;

/** Deterministic, PHI-free, tool-free prose so runChatTurn returns cleanly. */
function scriptedRuntime(text: string): LlmAgentRuntime {
  return {
    async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
      return { text, approxOutputTokens: 4, modelId: opts.modelId };
    },
  };
}

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  // Seat the offline FeatureHashEmbedder globally — runChatTurn's hybrid-search
  // preload and the M19 recall/embed paths both call getEmbedder().
  initEmbedderFromEnv();
  // Seat the Postgres lexical provider — runChatTurn's hybrid-search preload
  // (retrieveCandidates) calls getSearchProvider().
  initSearchProviderFromEnv();
  __setLlmRuntimeForTest(scriptedRuntime("Here is a summary of the audit status."));
  await new Promise<void>((resolve) => {
    server = createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

afterAll(async () => {
  __resetLlmRuntimeForTest();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  // The switch is read per-request from the env; never let one test leak the
  // flag into another (the default-off invariant must hold by default).
  delete process.env[RECALL_ENV];
});

class Client {
  private jar = new Map<string, string>();
  private cookieHeader(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  private absorb(res: Response): void {
    for (const raw of res.headers.getSetCookie()) {
      const pair = raw.split(";")[0]!;
      const i = pair.indexOf("=");
      if (i < 0) continue;
      this.jar.set(pair.slice(0, i), pair.slice(i + 1));
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

async function sessionClient(user: string): Promise<Client> {
  const c = new Client();
  const login = await c.post("/api/auth/login", { username: user, tenant_id: TENANT });
  expect(login.status).toBe(200);
  return c;
}

async function newSession(c: Client): Promise<string> {
  const res = await c.post("/api/chat/sessions", { title: `recall-${uniq()}` });
  expect(res.status).toBe(201);
  const body = (await res.json()) as { id: string };
  return body.id;
}

/** Send one chat turn and drain the SSE stream to completion. */
async function sendTurn(c: Client, sessionId: string, content: string): Promise<void> {
  const res = await c.post(`/api/chat/sessions/${sessionId}/messages`, { content });
  expect(res.status).toBe(200);
  await res.text(); // drain until the server closes the stream
}

/** Assert the turn completed: an assistant message is persisted. */
async function assistantReplied(c: Client, sessionId: string): Promise<boolean> {
  const res = await c.get(`/api/chat/sessions/${sessionId}/messages`);
  expect(res.status).toBe(200);
  const items = (await res.json()) as Array<{ role: string }>;
  return items.some((m) => m.role === "assistant");
}

/** Count embedding rows for a session (RLS-scoped via tenant context). */
async function embeddingCount(sessionId: string): Promise<number> {
  return withTenant(TENANT, async (tx) => {
    const r = await tx.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM chat_message_embeddings WHERE session_id = ${sessionId}`,
    );
    return r.rows[0]?.n ?? 0;
  });
}

describe("M19 chat semantic recall (route)", () => {
  it("switch OFF: a turn writes no embeddings (byte-identical to M18)", async () => {
    const c = await sessionClient(`off-${uniq()}`);
    const sessionId = await newSession(c);
    await sendTurn(c, sessionId, "what is the overall audit posture?");
    expect(await assistantReplied(c, sessionId)).toBe(true);
    expect(await embeddingCount(sessionId)).toBe(0);
  });

  it("switch ON: persisted user + assistant messages are embedded", async () => {
    process.env[RECALL_ENV] = "1";
    const c = await sessionClient(`on-${uniq()}`);
    const sessionId = await newSession(c);
    await sendTurn(c, sessionId, "summarize the open critical findings");
    // One user message + one assistant message embedded.
    expect(await embeddingCount(sessionId)).toBe(2);
    expect(await assistantReplied(c, sessionId)).toBe(true);
  });

  it("switch ON: a second turn recalls over prior embeddings and accumulates", async () => {
    process.env[RECALL_ENV] = "1";
    const c = await sessionClient(`on2-${uniq()}`);
    const sessionId = await newSession(c);
    await sendTurn(c, sessionId, "which log groups lack retention policies?");
    expect(await embeddingCount(sessionId)).toBe(2);
    // The second turn must actually run semantic recall over the first turn's
    // embeddings (priorCandidates non-empty) — not silently fall back. Spy on the
    // real implementation (kept intact) to prove the recall query fired with the
    // current turn's text, rather than only asserting the turn completed (which
    // would also pass under the recency-window fallback).
    const recallSpy = vi.spyOn(chatRecall, "semanticRecallMessageIds");
    const secondQuery = "and which of those also lack KMS encryption?";
    await sendTurn(c, sessionId, secondQuery);
    expect(recallSpy).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId, query: secondQuery }),
    );
    recallSpy.mockRestore();
    expect(await embeddingCount(sessionId)).toBe(4);
    expect(await assistantReplied(c, sessionId)).toBe(true);
  });

  it("switch ON: a fresh session with nothing to recall falls back to the recency window", async () => {
    process.env[RECALL_ENV] = "1";
    const c = await sessionClient(`fresh-${uniq()}`);
    const sessionId = await newSession(c);
    // First turn: no embeddings exist yet, so semantic recall yields no hits
    // and the replay window falls back to recency — the turn must still succeed.
    await sendTurn(c, sessionId, "give me a status overview");
    expect(await assistantReplied(c, sessionId)).toBe(true);
  });
});
