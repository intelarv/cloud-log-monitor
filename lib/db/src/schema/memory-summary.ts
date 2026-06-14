import {
  pgTable,
  text,
  integer,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

// Cross-finding consolidation summaries (opt-in, LLM-generated).
//
// The agent's vector memory (`finding_embeddings`) is bounded by
// `memory-eviction.ts`: Pass 1 CONSOLIDATION collapses a group of OLD/RESOLVED
// findings that share the same (classification, subclass, source) key down to a
// single highest-importance representative, evicting the duplicate embeddings.
// That collapse is deterministic and lossy at the *vector-recall* level — the
// individual embeddings of the duplicates are gone (the source findings in the
// append-only `findings` table are NEVER deleted).
//
// This table optionally captures, for each collapsed group, a short
// natural-language summary of what the group represents ("17 resolved SSN-in-log
// findings from billing-svc observed over 6 weeks, all remediated"). It is an
// OPT-IN enhancement (`MEMORY_CONSOLIDATION_SUMMARY`) layered on top of the
// already-built deterministic consolidation; when the switch is unset nothing is
// written here and behavior is byte-identical to pre-summary.
//
// PHI posture: the summary is generated from the REDACTED-only finding
// projection (the same redacted evidence the agent already sees) plus structural
// metadata, and the LLM output is re-scanned with `scanForPhi` before it is ever
// persisted or ledgered — so this table carries no raw PHI by construction.
//
// RLS-protected on tenant_id like every other tenant-scoped table; see
// setup-sql.ts. One row per (tenant_id, group_key); the summarizer upserts and
// skips groups whose membership signature is unchanged, so repeated sweeps do
// not re-call the LLM for a steady-state group.
export const memoryConsolidationSummariesTable = pgTable(
  "memory_consolidation_summaries",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull(),
    // NUL-joined (classification, subclass, source) — the consolidation group
    // identity, mirrors memory-eviction.ts groupKey().
    groupKey: text("group_key").notNull(),
    classification: text("classification").notNull(),
    subclass: text("subclass"),
    source: text("source").notNull(),
    // The kept (highest-importance) finding whose embedding survives eviction.
    representativeFindingId: text("representative_finding_id").notNull(),
    // How many findings collapsed into the representative (incl. representative).
    consolidatedCount: integer("consolidated_count").notNull(),
    // Hash of the sorted member id set; lets the summarizer skip re-summarizing
    // an unchanged group (idempotent, bounds LLM cost across sweeps/boots).
    memberSignature: text("member_signature").notNull(),
    // LLM-generated, redacted-input, PHI-rescanned natural-language summary.
    summary: text("summary").notNull(),
    // Effective model id that produced the summary (audit / non-repudiation).
    modelId: text("model_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex("memory_summary_tenant_group_idx").on(t.tenantId, t.groupKey),
  ],
);

export type MemoryConsolidationSummary =
  typeof memoryConsolidationSummariesTable.$inferSelect;
