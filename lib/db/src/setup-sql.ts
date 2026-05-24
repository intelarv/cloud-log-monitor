// Idempotent post-`drizzle-kit push` setup:
//  - Enables + FORCEs Row Level Security on tenant-scoped tables.
//  - Installs tenant isolation policies keyed on the `app.tenant_id` GUC.
//  - Creates the `findings_redacted` view (read-only projection — the
//    application should select from this view, never from `findings` directly,
//    so that future raw-evidence columns cannot be accidentally selected).
//
// Notes:
//  - `current_setting('app.tenant_id', true)` returns NULL when the GUC is
//    unset; `tenant_id = NULL` is NULL, so unset GUC => zero visible rows.
//    This is the safe default.
//  - The ledger table has NO row-level security; ledger reads are global
//    inside the trust boundary. (Production locks this down to the ledger
//    writer role; M0 has a single role.)
//  - Append-only at the DB layer: a row-level trigger raises on UPDATE/DELETE
//    of ledger_entries, so even the owner role cannot rewrite history outside
//    a deliberate, audited maintenance path (which would have to DROP TRIGGER
//    first — itself a control-plane event). Belt-and-suspenders for the
//    advisory-lock single-writer invariant in `appendLedger`.
//    See threat_model.md §Tampering and ARCHITECTURE.md §23.2.

// Default embedding dim. The actual dim is operator-configurable via the
// EMBEDDING_DIM env var read at boot; see embedder-config.ts. The column is
// created with the configured dim on first boot; subsequent boots with a
// different dim will fail at the runtime dim check in bootstrap.
export const DEFAULT_EMBEDDING_DIM = 256;

export interface SetupSqlOptions {
  /**
   * Vector dimension for finding_embeddings.embedding. Must match the
   * configured embedder's dim. Default 256 (FeatureHashEmbedder / Bedrock
   * Titan v2 small / Vertex outputDimensionality=256 / OpenAI v3 truncated).
   * Validated to be a positive integer ≤ 16000 (pgvector max).
   */
  embeddingDim?: number;
}

export function buildSetupSql(opts: SetupSqlOptions = {}): string {
  const dim = opts.embeddingDim ?? DEFAULT_EMBEDDING_DIM;
  if (!Number.isInteger(dim) || dim <= 0 || dim > 16000) {
    throw new Error(
      `buildSetupSql: embeddingDim must be a positive integer ≤ 16000, got ${dim}`,
    );
  }
  return `
-- M1: pgvector for semantic retrieval. Embeddings of redacted finding evidence
-- live in finding_embeddings; the embedder used in dev is a deterministic
-- feature-hash (see artifacts/api-server/src/lib/embeddings.ts). Production
-- selects a cloud-specific embedder via EMBEDDING_PROVIDER (bedrock / vertex /
-- azure-openai / tei) — the storage and search code do not change.
CREATE EXTENSION IF NOT EXISTS vector;

-- M1.6: ensure raw_evidence column exists on findings before any select-list
-- references it. Nullable jsonb; populated only for findings that carry an
-- unredacted source (canary in dev, detector-pipeline output in prod). The
-- column is NOT in the findings_redacted view — the only path that reads it
-- is the step-up-gated /admin/findings/:id/raw endpoint. See
-- threat_model.md §Info Disclosure.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS raw_evidence jsonb;

-- M5: multi-agent supervisor review state. Added idempotently so a DB
-- seeded under earlier milestones upgrades cleanly. Existing rows default
-- to 'pending' so the supervisor will eventually pick them up on the next
-- finding.created event (or via a manual replay). NULL verdicts mean the
-- specialist hasn't run yet; an empty {} would imply "ran and returned
-- nothing", which is a different state we never want to conflate.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS agent_review_status text NOT NULL DEFAULT 'pending';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triage_verdict jsonb;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verifier_verdict jsonb;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_agent_review_at timestamptz;

-- M1.6: one-shot idempotent backfill of the canary row's raw_evidence so a
-- DB seeded before M1.6 still demos the break-glass-read path. Targets
-- exactly one well-known synthetic row (F-CANARY) and only fires when the
-- column is NULL, so it's safe to run on every boot. Real-finding raw
-- backfill is out of scope here.
UPDATE findings
SET raw_evidence = jsonb_build_object(
  'snippet', redacted_evidence->>'snippet',
  'note', 'Synthetic canary payload backfilled by setup-sql; safe to surface in dev.'
)
WHERE id = 'F-CANARY' AND raw_evidence IS NULL;

-- M1.6: break-glass grants. Tenant-scoped, RLS-isolated. UPDATE is permitted
-- (revocation), DELETE is not enforced here at the DB level because every
-- grant's creation is *already* in the immutable ledger — losing the grant
-- row cannot hide it from auditors.
CREATE TABLE IF NOT EXISTS break_glass_grants (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  user_id text NOT NULL,
  finding_id text NOT NULL,
  justification text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
-- M1.7: two-person rule columns. Added idempotently so a DB seeded under
-- M1.6 upgrades cleanly. Existing rows default to requires_second_approval
-- = false, which preserves M1.6 single-analyst behavior for any
-- already-issued non-critical grants.
ALTER TABLE break_glass_grants
  ADD COLUMN IF NOT EXISTS requires_second_approval boolean NOT NULL DEFAULT false;
ALTER TABLE break_glass_grants
  ADD COLUMN IF NOT EXISTS approver_user_id text;
ALTER TABLE break_glass_grants
  ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE break_glass_grants
  ADD COLUMN IF NOT EXISTS approver_step_up_reason text;
-- M1.7: DB-level defense-in-depth for the two-person rule. Even if the
-- application layer regresses, the DB refuses to record an approval where
-- approver_user_id equals the requester's user_id. Added via DO block
-- because Postgres has no IF NOT EXISTS for table CHECK constraints.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'bg_no_self_approval'
      AND conrelid = 'break_glass_grants'::regclass
  ) THEN
    ALTER TABLE break_glass_grants
      ADD CONSTRAINT bg_no_self_approval
      CHECK (approver_user_id IS NULL OR approver_user_id <> user_id);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS bg_grants_tenant_user_idx
  ON break_glass_grants (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS bg_grants_lookup_idx
  ON break_glass_grants (tenant_id, user_id, finding_id, expires_at);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['findings', 'chat_sessions', 'chat_messages', 'break_glass_grants'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
      t
    );
  END LOOP;
END $$;

-- M1: full-text search index on findings.
-- We add a generated tsvector column composed from the redacted evidence
-- snippet, classification, subclass, and source — every searchable token in
-- M1 already passes through the redaction pipeline (threat model §Info
-- Disclosure: "Embeddings/FTS computed from redacted text only").
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS search_tsv tsvector
  GENERATED ALWAYS AS (
    setweight(to_tsvector('english', coalesce(classification, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(subclass, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(severity, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(source, '')), 'B') ||
    setweight(to_tsvector(
      'english',
      coalesce(redacted_evidence->>'snippet', '')
    ), 'C')
  ) STORED;

CREATE INDEX IF NOT EXISTS findings_search_tsv_idx
  ON findings USING GIN (search_tsv);

-- M1: vector embeddings table for findings. One row per finding, tenant-scoped
-- and RLS-isolated like the parent table. Vector dim is interpolated from
-- EMBEDDING_DIM and must match the configured embedder. Changing dim requires
-- DROP + recreate of this table (it's a cache; backfill rebuilds it).
CREATE TABLE IF NOT EXISTS finding_embeddings (
  finding_id text PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  content text NOT NULL,
  embedding vector(${dim}) NOT NULL,
  embedder_version text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS finding_embeddings_tenant_idx
  ON finding_embeddings (tenant_id);

-- ivfflat for cosine. M1 has only ~10 rows so a sequential scan beats the
-- index, but creating it now means production scale-up needs no schema work.
-- 'lists=10' is fine for tiny corpora; tune at scale.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE indexname = 'finding_embeddings_vec_idx'
  ) THEN
    EXECUTE 'CREATE INDEX finding_embeddings_vec_idx ON finding_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 10)';
  END IF;
END $$;

ALTER TABLE finding_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_embeddings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON finding_embeddings;
CREATE POLICY tenant_isolation ON finding_embeddings
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE VIEW findings_redacted AS
SELECT
  id,
  tenant_id,
  classification,
  subclass,
  severity,
  status,
  source,
  fingerprint,
  redacted_evidence,
  detector_version,
  first_seen_at,
  last_seen_at,
  occurrence_count
FROM findings;

-- Append-only enforcement for the ledger. This trigger function rejects any
-- UPDATE or DELETE against ledger_entries with a clear error code so callers
-- (drizzle, psql, anything) can detect the violation distinctly from a
-- generic constraint failure. INSERTs are unaffected.
CREATE OR REPLACE FUNCTION ledger_entries_append_only() RETURNS trigger AS $fn$
BEGIN
  RAISE EXCEPTION 'ledger_entries is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_entries_no_update ON ledger_entries;
CREATE TRIGGER ledger_entries_no_update
  BEFORE UPDATE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION ledger_entries_append_only();
-- ENABLE ALWAYS so the trigger fires even when session_replication_role is
-- set to 'replica' (logical replication apply, pg_restore --disable-triggers,
-- etc.) — closes the replication-replay bypass path.
ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_update;

DROP TRIGGER IF EXISTS ledger_entries_no_delete ON ledger_entries;
CREATE TRIGGER ledger_entries_no_delete
  BEFORE DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION ledger_entries_append_only();
ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_delete;

-- TRUNCATE also bypasses row-level triggers; cover it with a statement-level
-- trigger so the full {UPDATE, DELETE, TRUNCATE} set is locked down.
DROP TRIGGER IF EXISTS ledger_entries_no_truncate ON ledger_entries;
CREATE TRIGGER ledger_entries_no_truncate
  BEFORE TRUNCATE ON ledger_entries
  FOR EACH STATEMENT EXECUTE FUNCTION ledger_entries_append_only();
ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_truncate;

-- M2: ledger_checkpoints (external notarization). Same append-only lockdown
-- as ledger_entries — a checkpoint that can be rewritten is not a
-- checkpoint. In production this table additionally lives in a separate
-- account with Object Lock per §23.2; the ENABLE ALWAYS triggers here are
-- the dev/in-cluster equivalent.
--
-- Created idempotently here (rather than via drizzle push) so the triggers
-- below can reference it on first boot. Schema mirrors lib/db/src/schema/
-- checkpoints.ts; the two must stay in sync.
CREATE TABLE IF NOT EXISTS ledger_checkpoints (
  id bigserial PRIMARY KEY,
  seq bigint NOT NULL,
  head_hash text NOT NULL,
  notarized_at timestamptz NOT NULL DEFAULT now(),
  signature text NOT NULL,
  signing_key_id text NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ledger_checkpoints_seq_uniq
  ON ledger_checkpoints (seq);

CREATE OR REPLACE FUNCTION ledger_checkpoints_append_only() RETURNS trigger AS $fn$
BEGIN
  RAISE EXCEPTION 'ledger_checkpoints is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_checkpoints_no_update ON ledger_checkpoints;
CREATE TRIGGER ledger_checkpoints_no_update
  BEFORE UPDATE ON ledger_checkpoints
  FOR EACH ROW EXECUTE FUNCTION ledger_checkpoints_append_only();
ALTER TABLE ledger_checkpoints ENABLE ALWAYS TRIGGER ledger_checkpoints_no_update;

DROP TRIGGER IF EXISTS ledger_checkpoints_no_delete ON ledger_checkpoints;
CREATE TRIGGER ledger_checkpoints_no_delete
  BEFORE DELETE ON ledger_checkpoints
  FOR EACH ROW EXECUTE FUNCTION ledger_checkpoints_append_only();
ALTER TABLE ledger_checkpoints ENABLE ALWAYS TRIGGER ledger_checkpoints_no_delete;

DROP TRIGGER IF EXISTS ledger_checkpoints_no_truncate ON ledger_checkpoints;
CREATE TRIGGER ledger_checkpoints_no_truncate
  BEFORE TRUNCATE ON ledger_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION ledger_checkpoints_append_only();
ALTER TABLE ledger_checkpoints ENABLE ALWAYS TRIGGER ledger_checkpoints_no_truncate;
`;
}

// Backwards-compat constant: default-dim SQL used by older callers and tests.
// New code should call `buildSetupSql({ embeddingDim })` directly.
export const SETUP_SQL = buildSetupSql();
