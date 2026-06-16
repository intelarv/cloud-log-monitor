import {
  pgTable,
  text,
  jsonb,
  timestamp,
  integer,
  index,
} from "drizzle-orm/pg-core";

export const chatSessionsTable = pgTable(
  "chat_sessions",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull(),
    userId: text("user_id").notNull(),
    title: text("title"),
    // Chat working-memory rolling summary (opt-in CHAT_MEMORY_SUMMARY). Holds a
    // PHI-scanned natural-language summary of conversation turns that have
    // overflowed the sliding window; `coveredCount` is how many of the oldest
    // messages it represents so the next fold is incremental. See chat-memory.ts.
    memorySummary: text("memory_summary"),
    memorySummaryCoveredCount: integer("memory_summary_covered_count")
      .notNull()
      .default(0),
    memorySummaryModel: text("memory_summary_model"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [index("chat_sessions_tenant_user_idx").on(t.tenantId, t.userId)],
);

export const chatMessagesTable = pgTable(
  "chat_messages",
  {
    id: text("id").primaryKey(),
    sessionId: text("session_id").notNull(),
    tenantId: text("tenant_id").notNull(),
    role: text("role").notNull(),
    content: text("content").notNull(),
    citations: jsonb("citations").notNull().default([]),
    agentIdentity: jsonb("agent_identity"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    index("chat_messages_session_idx").on(t.sessionId, t.createdAt),
    index("chat_messages_tenant_idx").on(t.tenantId),
  ],
);

export type ChatSession = typeof chatSessionsTable.$inferSelect;
export type ChatMessage = typeof chatMessagesTable.$inferSelect;
