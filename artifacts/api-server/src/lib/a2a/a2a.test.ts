// A2A loopback round-trip test (credential-free, offline).
//
// Spins up the Triage + Verifier A2A servers on an ephemeral loopback port,
// then drives them through the real `A2AAgentInvoker` (official @a2a-js/sdk
// client → Agent Card resolution → JSON-RPC message/send). The agents'
// underlying LLM call is stubbed via the injectable runtime seam, so no
// network or credentials are required.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import express, { type Express } from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import type { FindingSafe } from "@workspace/db";
import {
  __setLlmRuntimeForTest,
  __resetLlmRuntimeForTest,
  type LlmAgentRuntime,
} from "../llm-runtime";
import { mountA2AAgents } from "./server";
import { A2AAgentInvoker } from "./client";
import {
  getA2ASharedSecret,
  __resetA2ASecretForTest,
  buildA2AClientFetch,
} from "./auth";
import { TRIAGE_AGENT_PATH, A2A_CARD_SUFFIX } from "./protocol";

const TRIAGE_JSON = JSON.stringify({
  recommended_severity: "critical",
  recommended_action: "page_oncall",
  rationale: "Redacted SSN in a production log group; page on-call.",
  confidence: 0.9,
  prompt_injection_suspected: false,
});
const VERIFIER_JSON = JSON.stringify({
  verdict: "true_positive",
  rationale: "Agrees with triage; redacted SSN pattern is genuine.",
  confidence: 0.85,
  prompt_injection_suspected: false,
  agrees_with_triage: true,
});

// Hands back the canned responses in order (one per agent call), like the
// supervisor suite's fake runtime — robust to prompt wording overlaps.
function makeRuntime(responses: string[]): LlmAgentRuntime {
  let i = 0;
  return {
    async generate(opts) {
      const text = responses[i++] ?? "";
      return { text, approxOutputTokens: Math.ceil(text.length / 4), modelId: opts.modelId };
    },
  };
}

const FINDING = {
  id: "F-A2A-TEST",
  tenantId: "default",
  classification: "phi",
  subclass: "ssn",
  severity: "high",
  status: "open",
  source: "test:a2a",
  fingerprint: "test:a2a",
  redactedEvidence: {
    snippet: "applicant_ssn=[REDACTED:ssn] status=retry",
    redactions: ["ssn"],
    truncated: false,
    trust: "untrusted",
  },
  detectorVersion: "test@0.0.0",
} as unknown as FindingSafe;

let server: Server;
let baseUrl: string;
let prevBaseUrl: string | undefined;

beforeAll(async () => {
  prevBaseUrl = process.env["A2A_BASE_URL"];
  const app: Express = express();
  app.use(express.json());
  mountA2AAgents(app);
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;
  process.env["A2A_BASE_URL"] = baseUrl;
  __resetA2ASecretForTest();
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
  if (prevBaseUrl === undefined) delete process.env["A2A_BASE_URL"];
  else process.env["A2A_BASE_URL"] = prevBaseUrl;
  __resetA2ASecretForTest();
});

afterEach(() => {
  __resetLlmRuntimeForTest();
});

describe("A2A loopback round-trip", () => {
  it("triage returns the verdict over the A2A protocol", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON]));
    const invoker = new A2AAgentInvoker(baseUrl);
    const out = await invoker.triage(FINDING);
    expect(out.verdict).toMatchObject({
      recommended_severity: "critical",
      recommended_action: "page_oncall",
      prompt_injection_suspected: false,
    });
    expect(out.approxOutputTokens).toBeGreaterThan(0);
    expect(out.modelId).toBeTruthy();
  });

  it("verify returns the verdict over the A2A protocol", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON, VERIFIER_JSON]));
    const invoker = new A2AAgentInvoker(baseUrl);
    const triage = (await invoker.triage(FINDING)).verdict;
    const out = await invoker.verify(FINDING, triage);
    expect(out.verdict).toMatchObject({
      verdict: "true_positive",
      agrees_with_triage: true,
    });
  });

  it("serves a valid Agent Card whose url points at the JSON-RPC endpoint", async () => {
    const res = await buildA2AClientFetch()(
      `${baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`,
    );
    expect(res.status).toBe(200);
    const card = (await res.json()) as { name: string; url: string; skills: unknown[] };
    expect(card.name).toBe("Triage Agent");
    expect(card.url).toBe(`${baseUrl}${TRIAGE_AGENT_PATH}`);
    expect(Array.isArray(card.skills)).toBe(true);
  });

  it("rejects an unauthenticated caller with 401", async () => {
    // Sanity: the shared secret is in effect.
    expect(getA2ASharedSecret().length).toBeGreaterThan(0);
    const res = await fetch(`${baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`);
    expect(res.status).toBe(401);
  });

  it("strips rawEvidence at the boundary — it never reaches the agent prompt", async () => {
    // A buggy/compromised caller sends a finding that smuggles raw PHI. The
    // executor must parse+strip so the agent (and thus the LLM prompt) never
    // sees it.
    const SENTINEL = "RAW-PHI-SENTINEL-999-88-7777";
    const prompts: string[] = [];
    __setLlmRuntimeForTest({
      async generate(opts) {
        prompts.push(opts.userPrompt);
        return { text: TRIAGE_JSON, approxOutputTokens: 8, modelId: opts.modelId };
      },
    });
    const poisoned = {
      ...(FINDING as unknown as Record<string, unknown>),
      rawEvidence: { snippet: SENTINEL },
      rawEvidenceRef: { first: SENTINEL, latest: SENTINEL },
    } as unknown as FindingSafe;

    const invoker = new A2AAgentInvoker(baseUrl);
    const out = await invoker.triage(poisoned);
    expect(out.verdict.recommended_severity).toBe("critical");
    expect(prompts.length).toBe(1);
    expect(prompts[0]).not.toContain(SENTINEL);
  });

  it("rejects a malformed finding payload (missing required field)", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON]));
    // Drop the required `id` field — schema parse in the executor must reject.
    const { id: _omit, ...rest } = FINDING as unknown as Record<string, unknown>;
    const malformed = rest as unknown as FindingSafe;
    const invoker = new A2AAgentInvoker(baseUrl);
    await expect(invoker.triage(malformed)).rejects.toThrow();
  });
});
