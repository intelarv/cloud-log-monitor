// A2A client side: the Supervisor's `AgentInvoker` implementations.
//
//   A2AAgentInvoker     — real A2A. Lazily resolves each agent's card over
//                         loopback, then `message/send`s the redacted finding
//                         and parses the structured verdict from the response.
//   inProcessAgentInvoker — direct function calls; used by tests to stay
//                         hermetic/offline (no HTTP, no port).
//
// The Supervisor depends only on `getAgentInvoker()`; production uses A2A,
// tests override with the in-process invoker.

import { randomUUID } from "node:crypto";
import { A2AClient } from "@a2a-js/sdk/client";
import type { DataPart, Message, Part, SendMessageResponse, Task } from "@a2a-js/sdk";
import type { FindingSafe } from "@workspace/db";
import { runTriageAgent } from "../agents/triage";
import { runVerifierAgent } from "../agents/verifier";
import { runContextAgent } from "../agents/context";
import { runNotifierAgent } from "../agents/notifier";
import type { TriageVerdict } from "../agents/triage";
import type { VerifierVerdict } from "../agents/verifier";
import type { ContextVerdict } from "../agents/context";
import {
  triageResponseSchema,
  verifyResponseSchema,
  contextResponseSchema,
  notifyResponseSchema,
  type AgentInvoker,
  type TriageInvokeResult,
  type VerifierInvokeResult,
  type ContextInvokeResult,
  type NotifierInvokeResult,
  TRIAGE_AGENT_PATH,
  VERIFY_AGENT_PATH,
  CONTEXT_AGENT_PATH,
  NOTIFY_AGENT_PATH,
  A2A_CARD_SUFFIX,
} from "./protocol";
import { buildA2AClientFetch, getA2ABaseUrl } from "./auth";
import {
  mintCallerToken,
  SUPERVISOR_CALLER_ID,
  TRIAGE_AUDIENCE,
  VERIFY_AUDIENCE,
  CONTEXT_AUDIENCE,
  NOTIFY_AUDIENCE,
  TRIAGE_SKILL,
  VERIFY_SKILL,
  CONTEXT_SKILL,
  NOTIFY_SKILL,
} from "./caller-identity";

function userDataMessage(data: Record<string, unknown>): Message {
  return {
    kind: "message",
    messageId: `msg_${randomUUID()}`,
    role: "user",
    parts: [{ kind: "data", data }],
  };
}

function firstDataPart(parts: Part[] | undefined): Record<string, unknown> | undefined {
  return parts?.find((p): p is DataPart => p.kind === "data")?.data;
}

// A spec-compliant A2A agent may answer `message/send` with either a `Message`
// (synchronous) or a `Task` (the handler created task state for the turn). We
// accept both and dig the structured verdict data part out of whichever shape
// arrived: a Message's parts, or a Task's terminal status message / artifacts /
// last agent history message.
function dataFromTask(task: Task): Record<string, unknown> | undefined {
  const fromStatus = firstDataPart(task.status.message?.parts);
  if (fromStatus !== undefined) return fromStatus;
  for (const artifact of task.artifacts ?? []) {
    const fromArtifact = firstDataPart(artifact.parts);
    if (fromArtifact !== undefined) return fromArtifact;
  }
  for (let i = (task.history?.length ?? 0) - 1; i >= 0; i--) {
    const msg = task.history?.[i];
    if (msg?.role === "agent") {
      const fromHistory = firstDataPart(msg.parts);
      if (fromHistory !== undefined) return fromHistory;
    }
  }
  return undefined;
}

function extractResponseData(res: SendMessageResponse, label: string): Record<string, unknown> {
  if ("error" in res) {
    throw new Error(`a2a ${label}: agent returned error ${res.error.code}: ${res.error.message}`);
  }
  const result = res.result;
  const data =
    result.kind === "message"
      ? firstDataPart(result.parts as Part[])
      : result.kind === "task"
        ? dataFromTask(result as Task)
        : undefined;
  if (data === undefined) {
    throw new Error(`a2a ${label}: no data part in ${result.kind} result`);
  }
  return data;
}

export class A2AAgentInvoker implements AgentInvoker {
  private readonly baseUrl: string;
  private triageClient?: Promise<A2AClient>;
  private verifierClient?: Promise<A2AClient>;
  private contextClient?: Promise<A2AClient>;
  private notifierClient?: Promise<A2AClient>;

  constructor(baseUrl: string = getA2ABaseUrl()) {
    this.baseUrl = baseUrl;
  }

  private triage_(): Promise<A2AClient> {
    return (this.triageClient ??= A2AClient.fromCardUrl(
      `${this.baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`,
      {
        fetchImpl: buildA2AClientFetch(() =>
          mintCallerToken({
            subject: SUPERVISOR_CALLER_ID,
            audience: TRIAGE_AUDIENCE,
            scope: [TRIAGE_SKILL],
          }),
        ),
      },
    ));
  }

  private verify_(): Promise<A2AClient> {
    return (this.verifierClient ??= A2AClient.fromCardUrl(
      `${this.baseUrl}${VERIFY_AGENT_PATH}${A2A_CARD_SUFFIX}`,
      {
        fetchImpl: buildA2AClientFetch(() =>
          mintCallerToken({
            subject: SUPERVISOR_CALLER_ID,
            audience: VERIFY_AUDIENCE,
            scope: [VERIFY_SKILL],
          }),
        ),
      },
    ));
  }

  async triage(finding: FindingSafe): Promise<TriageInvokeResult> {
    const client = await this.triage_();
    const res = await client.sendMessage({
      message: userDataMessage({ kind: "triage_request", finding }),
    });
    const parsed = triageResponseSchema.parse(extractResponseData(res, "triage"));
    return {
      verdict: parsed.verdict,
      approxOutputTokens: parsed.approxOutputTokens,
      modelId: parsed.modelId,
    };
  }

  async verify(finding: FindingSafe, triage: TriageVerdict): Promise<VerifierInvokeResult> {
    const client = await this.verify_();
    const res = await client.sendMessage({
      message: userDataMessage({ kind: "verify_request", finding, triage }),
    });
    const parsed = verifyResponseSchema.parse(extractResponseData(res, "verify"));
    return {
      verdict: parsed.verdict,
      approxOutputTokens: parsed.approxOutputTokens,
      modelId: parsed.modelId,
    };
  }

  private context_(): Promise<A2AClient> {
    return (this.contextClient ??= A2AClient.fromCardUrl(
      `${this.baseUrl}${CONTEXT_AGENT_PATH}${A2A_CARD_SUFFIX}`,
      {
        fetchImpl: buildA2AClientFetch(() =>
          mintCallerToken({
            subject: SUPERVISOR_CALLER_ID,
            audience: CONTEXT_AUDIENCE,
            scope: [CONTEXT_SKILL],
          }),
        ),
      },
    ));
  }

  private notify_(): Promise<A2AClient> {
    return (this.notifierClient ??= A2AClient.fromCardUrl(
      `${this.baseUrl}${NOTIFY_AGENT_PATH}${A2A_CARD_SUFFIX}`,
      {
        fetchImpl: buildA2AClientFetch(() =>
          mintCallerToken({
            subject: SUPERVISOR_CALLER_ID,
            audience: NOTIFY_AUDIENCE,
            scope: [NOTIFY_SKILL],
          }),
        ),
      },
    ));
  }

  async context(finding: FindingSafe): Promise<ContextInvokeResult> {
    const client = await this.context_();
    const res = await client.sendMessage({
      message: userDataMessage({ kind: "context_request", finding }),
    });
    const parsed = contextResponseSchema.parse(extractResponseData(res, "context"));
    return {
      verdict: parsed.verdict,
      approxOutputTokens: parsed.approxOutputTokens,
      modelId: parsed.modelId,
    };
  }

  async notify(
    finding: FindingSafe,
    triage: TriageVerdict,
    verifier: VerifierVerdict,
    context: ContextVerdict,
  ): Promise<NotifierInvokeResult> {
    const client = await this.notify_();
    const res = await client.sendMessage({
      message: userDataMessage({
        kind: "notify_request",
        finding,
        triage,
        verifier,
        context,
      }),
    });
    const parsed = notifyResponseSchema.parse(extractResponseData(res, "notify"));
    return {
      verdict: parsed.verdict,
      approxOutputTokens: parsed.approxOutputTokens,
      modelId: parsed.modelId,
    };
  }
}

/** Direct in-process invoker (no HTTP) — for hermetic offline tests. */
export const inProcessAgentInvoker: AgentInvoker = {
  triage(finding) {
    return runTriageAgent(finding);
  },
  verify(finding, triage) {
    return runVerifierAgent(finding, triage);
  },
  context(finding) {
    return runContextAgent(finding);
  },
  notify(finding, triage, verifier, context) {
    return runNotifierAgent(finding, triage, verifier, context);
  },
};

// ---------------------------------------------------------------------------
// Invoker seam used by the Supervisor.
// ---------------------------------------------------------------------------

let invokerOverride: AgentInvoker | null = null;
let defaultInvoker: AgentInvoker | null = null;

export function getAgentInvoker(): AgentInvoker {
  if (invokerOverride !== null) return invokerOverride;
  if (defaultInvoker === null) defaultInvoker = new A2AAgentInvoker();
  return defaultInvoker;
}

export function __setAgentInvokerForTest(invoker: AgentInvoker): void {
  invokerOverride = invoker;
}

export function __resetAgentInvokerForTest(): void {
  invokerOverride = null;
}
