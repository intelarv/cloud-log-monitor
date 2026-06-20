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
import {
  getChatMemoryConfigFromEnv,
  selectWindow,
  assembleRecallWindow,
  toHistoryTurns,
  summarizeChatOverflow,
  type StoredChatMessage,
  type RecallCandidate,
} from "../lib/chat-memory";
import {
  embedAndStoreChatMessage,
  semanticRecallMessageIds,
  hybridRecallMessageIds,
} from "../lib/chat-recall";
import { resolveLlmForDecisionPoint } from "../lib/llm-decision-points";
import { CHAT_AGENT_MODEL } from "../lib/prompts";

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
      const runId0 = `run_${randomUUID()}`;
      sse0.runStarted(sessionId, runId0);
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
      sse0.ledgerAppended(refLedger);
      sse0.assistantMessage(refuseMessageId, SAFE_REFUSAL, []);
      sse0.runFinished(sessionId, runId0);
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

    // ---- Working memory: token-budgeted sliding window (+ optional rolling
    // summary) over the persisted conversation. Built BEFORE the new user
    // message is inserted so the current question is not double-counted.
    // chat_messages content is already PHI-safe (input refused / output scanned
    // before persistence), so replaying it introduces no new raw PHI.
    const memCfg = getChatMemoryConfigFromEnv();
    // Loaded with ids (chronological) so semantic recall can dedupe + look up
    // similarity hits; the recency window/summary only needs {role, content}.
    const priorCandidates = await withTenant(tenantId, async (tx) => {
      const rows = await tx
        .select({
          id: chatMessagesTable.id,
          role: chatMessagesTable.role,
          content: chatMessagesTable.content,
        })
        .from(chatMessagesTable)
        .where(
          and(
            eq(chatMessagesTable.sessionId, sessionId),
            eq(chatMessagesTable.tenantId, tenantId),
          ),
        )
        .orderBy(asc(chatMessagesTable.createdAt))
        .limit(500);
      return rows
        .filter((r) => r.role === "user" || r.role === "assistant")
        .map((r) => ({
          id: r.id,
          role: r.role as "user" | "assistant",
          content: r.content,
        })) satisfies RecallCandidate[];
    });
    const priorMessages: StoredChatMessage[] = priorCandidates.map((m) => ({
      role: m.role,
      content: m.content,
    }));

    // The recency window + its overflow drive the M18 rolling summary (kept
    // byte-identical so the monotonic coveredCount invariant holds). Semantic
    // recall only swaps the REPLAYED window below — the two are orthogonal.
    const { window, overflow } = selectWindow(priorMessages, memCfg);

    // M19: when CHAT_MEMORY_SEMANTIC_RECALL is on, replay the most-RELEVANT
    // prior turns (pgvector cosine over per-message embeddings) ∪ a recency
    // tail, instead of pure recency. Best-effort: any failure (or no embeddings
    // yet) falls back to the recency window so a turn never breaks.
    let replayWindow = window;
    if (memCfg.semanticRecallEnabled && priorCandidates.length > 0) {
      try {
        // M-hybrid (opt-in CHAT_MEMORY_HYBRID_RECALL): fuse a lexical (BM25) leg
        // with the vector leg via RRF; off ⇒ vector-only (M19, byte-identical).
        const relevantIds = memCfg.hybridRecallEnabled
          ? await hybridRecallMessageIds({
              tenantId,
              sessionId,
              query: parsed.data.content,
              k: memCfg.semanticRecallK,
            })
          : await semanticRecallMessageIds({
              tenantId,
              sessionId,
              query: parsed.data.content,
              k: memCfg.semanticRecallK,
            });
        if (relevantIds.length > 0) {
          replayWindow = assembleRecallWindow(
            priorCandidates,
            relevantIds,
            memCfg,
          ).window;
        }
      } catch (err) {
        req.log.error(
          { err_name: err instanceof Error ? err.name : "unknown" },
          "chat semantic recall failed; falling back to recency window",
        );
      }
    }

    // Rolling summary (opt-in CHAT_MEMORY_SUMMARY). Fold any overflow not yet
    // represented by the stored summary into an updated summary, re-scan it for
    // PHI, persist, and ledger (counts + model only). Best-effort: any failure
    // keeps the prior summary and never breaks the turn.
    let summaryForPrompt: string | null = null;
    if (memCfg.summaryEnabled) {
      summaryForPrompt = session.memorySummary ?? null;
      // Snapshot the persisted coverage so the write below can compare-and-swap
      // against it — two turns racing on the same session must not roll the
      // counter back or clobber each other's summary.
      const storedCovered = session.memorySummaryCoveredCount ?? 0;
      const covered = Math.min(storedCovered, overflow.length);
      const newOverflow = overflow.slice(
        covered,
        covered + memCfg.summaryMaxMessages,
      );
      if (newOverflow.length > 0) {
        const { runtime, modelId } = resolveLlmForDecisionPoint(
          "chat",
          memCfg.summaryModel ?? CHAT_AGENT_MODEL,
        );
        try {
          const gen = await summarizeChatOverflow({
            runtime,
            modelId,
            priorSummary: summaryForPrompt,
            newMessages: newOverflow,
          });
          // Defense-in-depth: re-scan the model output before it is persisted or
          // used. Any hit keeps the prior summary and is ledgered (reason only).
          if (gen.text !== "" && scanForPhi(gen.text).length === 0) {
            // covered >= storedCovered is impossible to regress here: covered is
            // min(storedCovered, overflow.length) and newOverflow is non-empty
            // only when storedCovered <= overflow.length, so newCovered grows.
            const newCovered = covered + newOverflow.length;
            // Optimistic CAS on the snapshotted coverage: the update applies
            // only if no concurrent turn advanced the counter in the meantime.
            const updated = await withTenant(tenantId, async (tx) =>
              tx
                .update(chatSessionsTable)
                .set({
                  memorySummary: gen.text,
                  memorySummaryCoveredCount: newCovered,
                  memorySummaryModel: gen.modelId,
                })
                .where(
                  and(
                    eq(chatSessionsTable.id, sessionId),
                    eq(chatSessionsTable.tenantId, tenantId),
                    eq(
                      chatSessionsTable.memorySummaryCoveredCount,
                      storedCovered,
                    ),
                  ),
                )
                .returning({ id: chatSessionsTable.id }),
            );
            if (updated.length === 0) {
              // A concurrent turn already advanced the rolling summary. Keep the
              // prior summary for this turn's prompt (best-effort) and skip the
              // ledger write — nothing was persisted, so there is nothing to
              // attribute and re-folding happens on a later turn if needed.
              req.log.info(
                { session_id: sessionId },
                "chat memory summary skipped: concurrent update won the CAS",
              );
            } else {
              summaryForPrompt = gen.text;
              await appendLedger({
                tenantId,
                actor: { kind: "system", id: "chat_memory" },
                eventType: "chat.memory_summarized",
                subjectType: "chat_session",
                subjectId: sessionId,
                // Counts + model only — never message text, summary text, or PHI.
                payload: {
                  session_id: sessionId,
                  folded: newOverflow.length,
                  covered: newCovered,
                  model_id: gen.modelId,
                },
              });
            }
          } else {
            await appendLedger({
              tenantId,
              actor: { kind: "system", id: "chat_memory" },
              eventType: "chat.memory_summary_failed",
              subjectType: "chat_session",
              subjectId: sessionId,
              payload: {
                session_id: sessionId,
                error: gen.text === "" ? "empty_output" : "phi_in_output",
              },
            });
          }
        } catch (err) {
          req.log.error(
            { err_name: err instanceof Error ? err.name : "unknown" },
            "chat memory summarization failed; keeping prior summary",
          );
          await appendLedger({
            tenantId,
            actor: { kind: "system", id: "chat_memory" },
            eventType: "chat.memory_summary_failed",
            subjectType: "chat_session",
            subjectId: sessionId,
            payload: {
              session_id: sessionId,
              error: err instanceof Error ? err.name : "unknown",
            },
          });
        }
      }
    }

    const priorHistory = toHistoryTurns(replayWindow, summaryForPrompt);

    // Open SSE stream.
    const sse = new SseStream(res);
    const runId = `run_${randomUUID()}`;

    sse.runStarted(sessionId, runId);

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
    sse.userMessage(userMessageId, parsed.data.content);

    // M19: embed the user message for future semantic recall (opt-in). The
    // content is already PHI-safe and the embedder is PhiGuard-wrapped.
    // Best-effort — never break the turn if embedding/storage fails.
    if (memCfg.semanticRecallEnabled) {
      try {
        await embedAndStoreChatMessage({
          tenantId,
          sessionId,
          messageId: userMessageId,
          content: parsed.data.content,
        });
      } catch (err) {
        req.log.error(
          { err_name: err instanceof Error ? err.name : "unknown" },
          "chat recall: failed to embed user message",
        );
      }
    }

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
    sse.ledgerAppended(userLedger);

    sse.stepStarted("agent_thinking");

    const agentMessageId = `cm_${randomUUID()}`;
    let result;
    try {
      result = await runChatTurn({
        tenantId,
        userId,
        userQuestion: parsed.data.content,
        // Working memory: replay the token-budgeted window (+ rolling summary).
        priorHistory,
        // IMPORTANT: do NOT forward token deltas to SSE here. PHI in agent
        // output must be detected and replaced BEFORE anything reaches the
        // client. We accumulate the full response inside runChatTurn, run
        // scanForPhi below, then emit the final (possibly-refused) text as a
        // single delta. (ARCHITECTURE.md §23.1, threat model §Info Disclosure.)
        onDelta: undefined,
        onToolCall: (info) => {
          sse.toolCall(info.call_id, info.name, info.args);
        },
        onToolResult: (info) => {
          sse.toolResult(`tm_${randomUUID()}`, info.call_id, {
            ok: info.ok,
            result: info.result,
            error: info.error,
          });
        },
      });
    } catch (err) {
      // Log full error server-side, but only surface a generic message to the
      // client — error text can contain provider details or user-derived
      // content. (threat model §Info Disclosure.)
      req.log.error({ err }, "agent error");
      sse.runError("agent_error");
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
      sse.ledgerAppended(phiLedger);
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

    // M19: embed the assistant message for future semantic recall (opt-in).
    // finalText is post-PHI-scan (SAFE_REFUSAL if a hit was found) and the
    // embedder is PhiGuard-wrapped. Best-effort — never break the turn.
    if (memCfg.semanticRecallEnabled) {
      try {
        await embedAndStoreChatMessage({
          tenantId,
          sessionId,
          messageId: agentMessageId,
          content: finalText,
        });
      } catch (err) {
        req.log.error(
          { err_name: err instanceof Error ? err.name : "unknown" },
          "chat recall: failed to embed assistant message",
        );
      }
    }

    // Output was buffered in runChatTurn (no token deltas sent). Emit the
    // post-scan final text as a single AG-UI text message (START→CONTENT→END)
    // so the UI renders it. If the PHI scan triggered a replacement, this text
    // is SAFE_REFUSAL.
    sse.assistantMessage(agentMessageId, finalText, finalCitations);

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
        preloaded_finding_ids: result.preloaded_finding_ids,
        // Harness telemetry (threat model §DoS): record when a turn fell back
        // to a deterministic answer and the approximate output-token cost, so
        // an auditor can see degraded turns and cost trends from the ledger.
        degraded: result.degraded,
        ...(result.degrade_reason
          ? { degrade_reason: result.degrade_reason }
          : {}),
        approx_output_tokens: result.approx_output_tokens,
      },
    });
    sse.ledgerAppended(turnLedger);

    // RUN_FINISHED carries the harness telemetry (threat model §DoS) so a
    // client can surface degraded turns and approximate cost without a refetch.
    sse.runFinished(sessionId, runId, {
      degraded: result.degraded,
      ...(result.degrade_reason ? { degrade_reason: result.degrade_reason } : {}),
      approx_output_tokens: result.approx_output_tokens,
    });
    sse.close();
  },
);

export default router;
