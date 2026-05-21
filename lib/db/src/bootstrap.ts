import { sql } from "drizzle-orm";
import { db } from "./db";
import { SETUP_SQL } from "./setup-sql";
import { seedIfEmpty } from "./seed";

export interface BootstrapOptions {
  setup?: boolean;
  seed?: boolean;
}

export async function bootstrap(opts: BootstrapOptions = {}): Promise<{
  setup: boolean;
  seeded: boolean;
}> {
  const result = { setup: false, seeded: false };
  if (opts.setup !== false) {
    await db.execute(sql.raw(SETUP_SQL));
    result.setup = true;
  }
  if (opts.seed !== false) {
    result.seeded = await seedIfEmpty();
  }
  return result;
}
