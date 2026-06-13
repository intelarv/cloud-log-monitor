import { sql } from "drizzle-orm";
import { db } from "./db";
import { buildSetupSql, DEFAULT_EMBEDDING_DIM } from "./setup-sql";
import { seedIfEmpty } from "./seed";

export interface BootstrapOptions {
  setup?: boolean;
  seed?: boolean;
  /**
   * Vector dimension to apply to `finding_embeddings.embedding`. Must match
   * the embedder configured at the API layer. Default 256.
   *
   * On boot we additionally verify that the existing column dim (if the table
   * was previously created with a different dim) matches the configured one;
   * mismatch is a hard error pointing the operator to DROP + recreate.
   */
  embeddingDim?: number;
  /**
   * M12.2: opt-in LIST-partitioning of finding_embeddings by tenant_id (default
   * false ⇒ original single-table layout, byte-identical). Driven by
   * EMBEDDINGS_TENANT_PARTITIONING at the API layer. See setup-sql.ts.
   */
  tenantPartitioning?: boolean;
}

export interface BootstrapResult {
  setup: boolean;
  seeded: boolean;
  embeddingDim: number;
}

export async function bootstrap(
  opts: BootstrapOptions = {},
): Promise<BootstrapResult> {
  const embeddingDim = opts.embeddingDim ?? DEFAULT_EMBEDDING_DIM;
  const result: BootstrapResult = { setup: false, seeded: false, embeddingDim };

  if (opts.setup !== false) {
    await db.execute(
      sql.raw(
        buildSetupSql({
          embeddingDim,
          tenantPartitioning: opts.tenantPartitioning === true,
        }),
      ),
    );
    result.setup = true;

    // Runtime dim invariant check: if the column already existed with a
    // different dim, `CREATE TABLE IF NOT EXISTS` silently kept the old one.
    // Detect that here and fail loudly.
    const actual = await getEmbeddingColumnDim();
    if (actual != null && actual !== embeddingDim) {
      throw new Error(
        `finding_embeddings.embedding column dim (${actual}) does not match ` +
          `configured EMBEDDING_DIM (${embeddingDim}). To change dims: ` +
          `DROP TABLE finding_embeddings; restart. (Embeddings are a cache; ` +
          `backfill will rebuild them.)`,
      );
    }
  }
  if (opts.seed !== false) {
    result.seeded = await seedIfEmpty();
  }
  return result;
}

// Inspect pg_attribute / pg_type to recover the vector(N) declared dim.
// pgvector encodes N in atttypmod as `N + VARHDRSZ` historically, but the
// portable path is to parse `format_type(atttypid, atttypmod)` which yields
// e.g. "vector(256)". Returns null if the table doesn't exist yet.
async function getEmbeddingColumnDim(): Promise<number | null> {
  const rows = await db.execute<{ formatted: string }>(sql`
    SELECT format_type(a.atttypid, a.atttypmod) AS formatted
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    WHERE c.relname = 'finding_embeddings'
      AND a.attname = 'embedding'
      AND a.attnum > 0
      AND NOT a.attisdropped
    LIMIT 1
  `);
  const formatted = rows.rows[0]?.formatted;
  if (!formatted) return null;
  const m = /^vector\((\d+)\)$/.exec(formatted);
  return m ? Number(m[1]) : null;
}
