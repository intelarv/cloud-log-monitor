// A2A AgentExecutors (threat_model §Elevation of Privilege — per-agent scope).
//
// Each executor is the server-side handler the A2A `DefaultRequestHandler`
// invokes on `message/send`. It reads the redacted finding out of the inbound
// DataPart, runs the existing in-process agent logic (`runTriageAgent` /
// `runVerifierAgent`, which route through the `LlmAgentRuntime` seam — so the
// PHI-guard wrapper and the offline test runtime still apply), and publishes a
// single response Message carrying the structured verdict back as a DataPart.
//
// The agents read ONLY the redacted finding fields; `rawEvidence` never crosses
// this boundary because the Supervisor sends `FindingSafe`.

import { randomUUID } from "node:crypto";
import type {
  AgentExecutor,
  ExecutionEventBus,
  RequestContext,
} from "@a2a-js/sdk/server";
import type { DataPart, Message, Part } from "@a2a-js/sdk";
import type { FindingSafe } from "@workspace/db";
import { logger } from "../logger";
import { runTriageAgent } from "../agents/triage";
import { runVerifierAgent } from "../agents/verifier";
import {
  triageRequestSchema,
  verifyRequestSchema,
  type TriageInvokeResult,
  type VerifierInvokeResult,
} from "./protocol";

function firstDataPart(parts: Part[]): DataPart | undefined {
  return parts.find((p): p is DataPart => p.kind === "data");
}

function makeResponseMessage(data: object): Message {
  return {
    kind: "message",
    messageId: `msg_${randomUUID()}`,
    role: "agent",
    parts: [{ kind: "data", data: data as Record<string, unknown> }],
  };
}

export class TriageExecutor implements AgentExecutor {
  async execute(ctx: RequestContext, bus: ExecutionEventBus): Promise<void> {
    const part = firstDataPart(ctx.userMessage.parts);
    if (part === undefined) {
      throw new Error("triage agent: request message has no data part");
    }
    // Parse + STRIP: forward only the schema-validated finding projection (Zod
    // drops any unexpected key, so `rawEvidence` can't cross even if a caller
    // included it). The cast narrows the stripped allow-list to FindingSafe; the
    // agent reads only the redacted fields present here.
    const req = triageRequestSchema.parse(part.data);
    const finding = req.finding as unknown as FindingSafe;

    const out = await runTriageAgent(finding);
    const payload: TriageInvokeResult & { kind: "triage_response" } = {
      kind: "triage_response",
      verdict: out.verdict,
      approxOutputTokens: out.approxOutputTokens,
      modelId: out.modelId,
    };
    bus.publish(makeResponseMessage(payload));
    bus.finished();
  }

  async cancelTask(taskId: string, _bus: ExecutionEventBus): Promise<void> {
    // Synchronous request/response; nothing long-running to cancel.
    logger.debug({ taskId }, "triage agent: cancelTask is a no-op");
  }
}

export class VerifierExecutor implements AgentExecutor {
  async execute(ctx: RequestContext, bus: ExecutionEventBus): Promise<void> {
    const part = firstDataPart(ctx.userMessage.parts);
    if (part === undefined) {
      throw new Error("verifier agent: request message has no data part");
    }
    // Parse + STRIP (see TriageExecutor): forward only the validated, redacted
    // finding projection — unexpected keys (incl. rawEvidence) are dropped.
    const req = verifyRequestSchema.parse(part.data);
    const finding = req.finding as unknown as FindingSafe;

    const out = await runVerifierAgent(finding, req.triage);
    const payload: VerifierInvokeResult & { kind: "verify_response" } = {
      kind: "verify_response",
      verdict: out.verdict,
      approxOutputTokens: out.approxOutputTokens,
      modelId: out.modelId,
    };
    bus.publish(makeResponseMessage(payload));
    bus.finished();
  }

  async cancelTask(taskId: string, _bus: ExecutionEventBus): Promise<void> {
    logger.debug({ taskId }, "verifier agent: cancelTask is a no-op");
  }
}
