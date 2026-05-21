import { sql } from "drizzle-orm";
import { db } from "@workspace/db";

// Wrap a unit of work in a transaction with the per-request tenant GUC set
// via `set_config(..., is_local=true)` so RLS policies on findings /
// chat_sessions / chat_messages enforce isolation. The GUC scope is the
// transaction; on commit/rollback PG resets it for the next pooled query.
export async function withTenant<T>(
  tenantId: string,
  fn: (tx: Parameters<Parameters<typeof db.transaction>[0]>[0]) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('app.tenant_id', ${tenantId}, true)`);
    return fn(tx);
  });
}
