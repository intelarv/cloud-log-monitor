import {
  pgTable,
  text,
  jsonb,
  timestamp,
  bigserial,
  uniqueIndex,
  index,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { z } from "zod/v4";

export const ledgerEntriesTable = pgTable(
  "ledger_entries",
  {
    seq: bigserial("seq", { mode: "number" }).primaryKey(),
    ts: timestamp("ts", { withTimezone: true }).notNull().defaultNow(),
    tenantId: text("tenant_id"),
    actor: jsonb("actor").notNull(),
    eventType: text("event_type").notNull(),
    subjectType: text("subject_type"),
    subjectId: text("subject_id"),
    payload: jsonb("payload").notNull(),
    prevHash: text("prev_hash").notNull(),
    hash: text("hash").notNull(),
  },
  (t) => [
    uniqueIndex("ledger_hash_uniq").on(t.hash),
    index("ledger_tenant_idx").on(t.tenantId),
    index("ledger_subject_idx").on(t.subjectType, t.subjectId),
    // Expression index backing the server-side actor pivot in routes/ledger.ts
    // ("show me everything this analyst did"): the query filters on
    // `tenant_id` + `actor->>'id'` (with a `kind = 'human'` recheck). Without
    // this index the filtered scan degrades on a large ledger within a tenant.
    index("ledger_actor_id_idx").on(t.tenantId, sql`((${t.actor}->>'id'))`),
  ],
);

export type LedgerEntry = typeof ledgerEntriesTable.$inferSelect;

export const ActorSchema = z.object({
  kind: z.enum(["human", "agent", "system"]),
  id: z.string(),
  display_name: z.string().optional(),
  agent_version: z.string().optional(),
  model_id: z.string().optional(),
  prompt_hash: z.string().optional(),
});
export type Actor = z.infer<typeof ActorSchema>;
