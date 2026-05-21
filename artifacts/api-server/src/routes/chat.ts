import { randomUUID, createHash } from "node:crypto";
import { Router, type IRouter } from "express";
import { asc, eq, and, desc } from "drizzle-orm";
import {
  chatMessagesTable,
  chatSessionsTable,
  findingsTable,
} from "@workspace/db";
import {
  ListChatMessagesResponseItem as ChatMessageSchema,
  SendChatMessageBody as ChatMessageInput,
  ListChatSessionsResponseItem as ChatSessionSchema,
  CreateChatSessionBody as ChatSessionInput,
} from "@workspace/api-zod";
import { withTenant } from "../lib/db-context";
import { requireSession } from "../lib/auth";
import { SseStream } from "../lib/sse";
import { appendLedger } from "../lib/ledger";
import { runChatTurn } from "../lib/chat-agent";
import { scanForPhi, SAFE_REFUSAL } from "../lib/redact";

const router: IRouter = Router();

function rowToApi(row: typeof chatMessagesTable.$inferSelect): unknown {
  return {
    id: row.id,
    session_id: row.sessionId,
    tenant_id: row.tenantId,
    role: row.role,
    content: row.content,
    citations: row.citations as string[],
    agent_identity: row.agentIdentity,
    created_at: row.createdAt.toISOString(),
  };
}

function sessionToApi(row: typeof chatSessionsTable.$inferSelect): unknown {
  return {
    id: row.id,
    tenant_id: row.tenantId,
    user_id: row.userId,
    title: row.title,
    created_at: row.createdAt.toISOString(),
  };
}

// ---------- Sessions ----------

router.get("/chat/sessions", requireSession, async (req, res): Promise<void> => {
  const tenantId = req.session!.tenant_id;
  const userId = req.session!.sub;
  const rows = await withTenant(tenantId, async (tx) =>
    tx
      .select()
      .from(chatSessionsTable)
      .where(
        and(
          eq(chatSessionsTable.tenantId, tenantId),
          eq(chatSessionsTable.userId, userId),
        ),
      )
      .orderBy(desc(chatSessionsTable.createdAt))
      .limit(50),
  );
  res.json(rows.map((r) => ChatSessionSchema.parse(sessionToApi(r))));
});

router.post("/chat/sessions", requireSession, async (req, res): Promise<void> => {
  const parsed = ChatSessionInput.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const tenantId = req.session!.tenant_id;
  const userId = req.session!.sub;
  const id = `cs_${randomUUID()}`;
  const [row] = await withTenant(tenantId, async (tx) =>
    tx
      .insert(chatSessionsTable)
      .values({ id, tenantId, userId, title: parsed.data.title ?? null })
      .returning(),
  );
  res.status(201).json(ChatSessionSchema.parse(sessionToApi(row!)));
});

// ---------- Messages ----------

router.get(
  "/chat/sessions/:id/messages",
  requireSession,
  async (req, res): Promise<void> => {
    const id = String(req.params.id);
    const tenantId = req.session!.tenant_id;
    const rows = await withTenant(tenantId, async (tx) =>
      tx
        .select()
        .from(chatMessagesTable)
        .where(
          and(
            eq(chatMessagesTable.sessionId, id),
            eq(chatMessagesTable.tenantId, tenantId),
          ),
        )
        .orderBy(asc(chatMessagesTable.createdAt))
        .limit(500),
    );
    res.json(rows.map((r) => ChatMessageSchema.parse(rowToApi(r))));
  },
);

// POST /chat/sessions/:id/messages returns text/event-stream (AG-UI envelope).
router.post(
  "/chat/sessions/:id/messages",
  requireSession,
  async (req, res): Promise<void> => {
    const sessionId = String(req.params.id);
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;

    const parsed = ChatMessageInput.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }

    // Input PHI scan. PHI MUST NOT reach LLM prompts (threat model §Info
    // Disclosure, ARCHITECTURE.md §23.1). Reject before the prompt is built,
    // emit a finding about the *input*, and respond with SAFE_REFUSAL.
    const inputPhiHits = scanForPhi(parsed.data.content);
    if (inputPhiHits.length > 0) {
      const sse0 = new SseStream(res);
      const ts = () => new Date().toISOString();
      sse0.send({ type: "session_started", session_id: sessionId, ts: ts() });
      const refuseMessageId = `cm_${randomUUID()}`;
      const findingId = `F-INPUT-PHI-${randomUUID().slice(0, 8)}`;
      await withTenant(tenantId, async (tx) =>
        tx.insert(findingsTable).values({
          id: findingId,
          tenantId,
          classification: "phi_in_output",
          subclass: `input:${inputPhiHits[0]!.detector}`,
          severity: "high",
          status: "open",
          source: `chat:user:${userId}`,
          fingerprint: `phi_in_input:${inputPhiHits[0]!.detector}:${userId}`,
          redactedEvidence: {
            snippet: `<REDACTED: user supplied ${inputPhiHits.length} PHI/PII match(es)>`,
            redactions: inputPhiHits.map((h) => h.detector),
            truncated: true,
            trust: "untrusted",
          },
          detectorVersion: "input-scan@m0",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          occurrenceCount: 1,
        }),
      );
      const refLedger = await appendLedger({
        tenantId,
        actor: { kind: "human", id: userId },
        eventType: "chat.input_phi_refused",
        subjectType: "finding",
        subjectId: findingId,
        payload: {
          session_id: sessionId,
          finding_id: findingId,
          // Hashes + counts only — never raw input.
          content_sha256: createHash("sha256")
            .update(parsed.data.content)
            .digest("hex"),
          content_length: parsed.data.content.length,
          hit_count: inputPhiHits.length,
          detectors: inputPhiHits.map((h) => h.detector),
        },
      });
      sse0.send({
        type: "ledger_appended",
        seq: refLedger.seq,
        event_type: refLedger.eventType,
        hash: refLedger.hash,
        ts: ts(),
      });
      sse0.send({
        type: "agent_message_delta",
        message_id: refuseMessageId,
        delta: SAFE_REFUSAL,
        ts: ts(),
      });
      sse0.send({
        type: "agent_message_complete",
        message_id: refuseMessageId,
        citations: [],
        ts: ts(),
      });
      sse0.send({ type: "done", ts: ts() });
      sse0.close();
      return;
    }

    // Verify the session belongs to this tenant+user.
    const session = await withTenant(tenantId, async (tx) => {
      const [row] = await tx
        .select()
        .from(chatSessionsTable)
        .where(
          and(
            eq(chatSessionsTable.id, sessionId),
            eq(chatSessionsTable.tenantId, tenantId),
            eq(chatSessionsTable.userId, userId),
          ),
        )
        .limit(1);
      return row;
    });
    if (!session) {
      res.status(404).json({ error: "session not found" });
      return;
    }

    // Open SSE stream.
    const sse = new SseStream(res);
    const now = () => new Date().toISOString();

    sse.send({ type: "session_started", session_id: sessionId, ts: now() });

    // Persist user message + ledger entry.
    const userMessageId = `cm_${randomUUID()}`;
    await withTenant(tenantId, async (tx) =>
      tx.insert(chatMessagesTable).values({
        id: userMessageId,
        sessionId,
        tenantId,
        role: "user",
        content: parsed.data.content,
        citations: [],
        agentIdentity: null,
      }),
    );
    sse.send({
      type: "user_message",
      message_id: userMessageId,
      content: parsed.data.content,
      ts: now(),
    });

    const contentHash = createHash("sha256")
      .update(parsed.data.content)
      .digest("hex");
    const userLedger = await appendLedger({
      tenantId,
      actor: { kind: "human", id: userId },
      eventType: "chat.user_turn",
      subjectType: "chat_session",
      subjectId: sessionId,
      // PHI must not appear in the ledger payload — store a content hash, not
      // the raw question. The redacted form is recoverable from chat_messages
      // (which is tenant-scoped + RLS-protected).
      payload: {
        session_id: sessionId,
        message_id: userMessageId,
        content_sha256: contentHash,
        content_length: parsed.data.content.length,
      },
    });
    sse.send({
      type: "ledger_appended",
      seq: userLedger.seq,
      event_type: userLedger.eventType,
      hash: userLedger.hash,
      ts: now(),
    });

    sse.send({ type: "agent_thinking", ts: now() });

    const agentMessageId = `cm_${randomUUID()}`;
    let result;
    try {
      result = await runChatTurn({
        tenantId,
        userId,
        userQuestion: parsed.data.content,
        // IMPORTANT: do NOT forward token deltas to SSE here. PHI in agent
        // output must be detected and replaced BEFORE anything reaches the
        // client. We accumulate the full response inside runChatTurn, run
        // scanForPhi below, then emit the final (possibly-refused) text as a
        // single delta. (ARCHITECTURE.md §23.1, threat model §Info Disclosure.)
        onDelta: undefined,
        onToolCall: (info) => {
          sse.send({
            type: "tool_call",
            call_id: info.call_id,
            tool: info.name,
            args: info.args,
            ts: now(),
          });
        },
        onToolResult: (info) => {
          sse.send({
            type: "tool_result",
            call_id: info.call_id,
            ok: info.ok,
            result: info.result,
            error: info.error,
            ts: now(),
          });
        },
      });
    } catch (err) {
      // Log full error server-side, but only surface a generic message to the
      // client — error text can contain provider details or user-derived
      // content. (threat model §Info Disclosure.)
      req.log.error({ err }, "agent error");
      sse.send({
        type: "error",
        error: "agent_error",
        ts: now(),
      });
      sse.send({ type: "done", ts: now() });
      sse.close();
      return;
    }

    // Output PHI scan. If the agent emitted anything that looks like raw
    // PHI/PII/secrets, replace the message with a safe refusal and emit a
    // finding *about the agent's output*. See ARCHITECTURE.md §23.1.
    const phiHits = scanForPhi(result.text);
    let finalText = result.text;
    let finalCitations = result.citations;
    if (phiHits.length > 0) {
      finalText = SAFE_REFUSAL;
      finalCitations = [];
      const detectorBreakdown = phiHits.map((h) => ({
        detector: h.detector,
        classification: h.classification,
        start: h.start,
        end: h.end,
      }));
      const findingId = `F-AGENT-OUT-${randomUUID().slice(0, 8)}`;
      await withTenant(tenantId, async (tx) =>
        tx.insert(findingsTable).values({
          id: findingId,
          tenantId,
          classification: "phi_in_output",
          subclass: phiHits[0]!.detector,
          severity: "critical",
          status: "open",
          source: `agent:chat:${agentMessageId}`,
          fingerprint: `phi_in_output:${phiHits[0]!.detector}:chat-agent`,
          redactedEvidence: {
            snippet: `<REDACTED: ${phiHits.length} hits across ${phiHits.length} positions>`,
            redactions: phiHits.map((h) => h.detector),
            truncated: true,
            trust: "untrusted",
          },
          detectorVersion: "output-scan@m0",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          occurrenceCount: 1,
        }),
      );
      const phiLedger = await appendLedger({
        tenantId,
        actor: {
          kind: "agent",
          id: "chat-agent",
          agent_version: result.agent_identity.agent_version,
          model_id: result.agent_identity.model_id,
          prompt_hash: result.agent_identity.prompt_hash,
        },
        eventType: "agent.output_phi_detected",
        subjectType: "finding",
        subjectId: findingId,
        payload: {
          session_id: sessionId,
          message_id: agentMessageId,
          finding_id: findingId,
          hits: detectorBreakdown,
        },
      });
      sse.send({
        type: "ledger_appended",
        seq: phiLedger.seq,
        event_type: phiLedger.eventType,
        hash: phiLedger.hash,
        ts: now(),
      });
    }

    // Persist agent message + ledger entry for the turn itself.
    await withTenant(tenantId, async (tx) =>
      tx.insert(chatMessagesTable).values({
        id: agentMessageId,
        sessionId,
        tenantId,
        role: "assistant",
        content: finalText,
        citations: finalCitations,
        agentIdentity: result.agent_identity,
      }),
    );

    // Output was buffered in runChatTurn (no token deltas sent). Emit the
    // post-scan final text as a single delta so the UI renders it. If the
    // PHI scan triggered a replacement, this delta is SAFE_REFUSAL.
    sse.send({
      type: "agent_message_delta",
      message_id: agentMessageId,
      delta: finalText,
      ts: now(),
    });

    sse.send({
      type: "agent_message_complete",
      message_id: agentMessageId,
      citations: finalCitations,
      ts: now(),
    });

    const turnLedger = await appendLedger({
      tenantId,
      actor: {
        kind: "agent",
        id: "chat-agent",
        agent_version: result.agent_identity.agent_version,
        model_id: result.agent_identity.model_id,
        prompt_hash: result.agent_identity.prompt_hash,
      },
      eventType: "chat.agent_turn",
      subjectType: "chat_session",
      subjectId: sessionId,
      payload: {
        session_id: sessionId,
        message_id: agentMessageId,
        // Ledger payload carries hashes + counts, never raw text.
        response_sha256: createHash("sha256").update(finalText).digest("hex"),
        response_length: finalText.length,
        citations: finalCitations,
        tool_calls: result.tool_calls.map((c) => ({
          name: c.name,
          ok: c.ok,
          error: c.error,
        })),
        phi_in_output_hits: phiHits.length,
        tool_versions: result.agent_identity.tool_versions,
      },
    });
    sse.send({
      type: "ledger_appended",
      seq: turnLedger.seq,
      event_type: turnLedger.eventType,
      hash: turnLedger.hash,
      ts: now(),
    });

    sse.send({ type: "done", ts: now() });
    sse.close();
  },
);

export default router;
