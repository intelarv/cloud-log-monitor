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
export const SETUP_SQL = `
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['findings', 'chat_sessions', 'chat_messages'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
      t
    );
  END LOOP;
END $$;

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
`;
