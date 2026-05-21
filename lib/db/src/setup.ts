// CLI: `pnpm --filter @workspace/db run setup`
import { sql } from "drizzle-orm";
import { db, pool } from "./db";
import { SETUP_SQL } from "./setup-sql";

async function main(): Promise<void> {
  await db.execute(sql.raw(SETUP_SQL));
  // eslint-disable-next-line no-console
  console.log("Setup SQL applied (RLS policies + findings_redacted view).");
  await pool.end();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("Setup failed:", err);
  process.exit(1);
});
