// Operator command: rebuild the external lexical (OpenSearch) index from the
// findings table.
//
// When `SEARCH_PROVIDER=opensearch`, the searchable mirror is maintained
// best-effort on ingest + reconciled at boot. This command lets an operator
// force a full, batched, resumable rebuild out-of-band — e.g. after pointing at
// a fresh cluster, recovering from a cluster-side data loss, or flipping
// `OPENSEARCH_PER_TENANT_INDEX` (which changes which physical index each
// tenant's docs live in).
//
// It reuses the exact same `reconcileSearchIndex` path the boot reconcile uses,
// so there is no second copy of the mirror logic. Reads go through the safe
// projection only — raw evidence never reaches the searchable tier.
//
// Usage (after `pnpm --filter @workspace/api-server run build`):
//   node dist/scripts/reindex-search.mjs [--batch-size=N] \
//     [--since-tenant=<tenantId> --since-id=<findingId>]
// or via the package script:
//   pnpm --filter @workspace/api-server run reindex:search -- --batch-size=1000
//
// To resume an interrupted run, copy BOTH values from its last progress line
// (`tenantId` + `lastId`) into `--since-tenant` + `--since-id`. The scan visits
// tenants in tenant_id order, so resuming needs the tenant as well as the id —
// a bare id is ambiguous across tenants and is rejected. Resume assumes the
// tenant set is unchanged since the interrupted run; for a guaranteed-complete
// pass (e.g. after tenants were added/removed) run without the resume flags.
//
// Requires DATABASE_URL + SEARCH_PROVIDER=opensearch (+ OPENSEARCH_* env). It
// is a no-op for the Postgres provider (its generated tsv column is always in
// sync); the command reports that and exits 0.
import { logger } from "../lib/logger";
import { initSearchProviderFromEnv } from "../lib/search-config";
import { reconcileSearchIndex, resolveReindexBatchSize } from "../lib/search";

interface CliArgs {
  batchSize?: number;
  resumeFrom?: { tenantId: string; sinceId: string };
}

function parseArgs(argv: ReadonlyArray<string>): CliArgs {
  let batchSize: number | undefined;
  let sinceTenant: string | undefined;
  let sinceId: string | undefined;
  for (const arg of argv) {
    const m = /^--([^=]+)=(.*)$/.exec(arg);
    if (!m) continue;
    const [, key, value] = m;
    if (key === "batch-size") {
      const n = Number(value);
      if (!Number.isInteger(n) || n <= 0) {
        throw new Error(`--batch-size must be a positive integer, got "${value}"`);
      }
      batchSize = n;
    } else if (key === "since-tenant") {
      if (value && value.trim()) sinceTenant = value.trim();
    } else if (key === "since-id") {
      if (value && value.trim()) sinceId = value.trim();
    } else {
      throw new Error(`Unknown flag: --${key}`);
    }
  }
  // Resume needs both the tenant and the id: tenants are scanned in tenant_id
  // order, so a bare id is ambiguous across tenants. Refuse a half-specified
  // resume rather than silently misinterpret it.
  if ((sinceTenant === undefined) !== (sinceId === undefined)) {
    throw new Error(
      "--since-tenant and --since-id must be provided together (copy both " +
        "from the last progress line); a bare --since-id is ambiguous across " +
        "tenants.",
    );
  }
  const out: CliArgs = {};
  if (batchSize !== undefined) out.batchSize = batchSize;
  if (sinceTenant !== undefined && sinceId !== undefined) {
    out.resumeFrom = { tenantId: sinceTenant, sinceId };
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const { provider } = initSearchProviderFromEnv();

  if (!provider.maintainsExternalIndex) {
    logger.info(
      { provider: provider.name },
      "reindex-search: provider maintains no external index (Postgres FTS is " +
        "always in sync); nothing to do.",
    );
    return;
  }

  const batchSize = args.batchSize ?? resolveReindexBatchSize();
  logger.info(
    { provider: provider.name, batchSize, resumeFrom: args.resumeFrom ?? null },
    args.resumeFrom ? "reindex-search: resuming reindex" : "reindex-search: starting full reindex",
  );

  const result = await reconcileSearchIndex({
    batchSize,
    ...(args.resumeFrom ? { resumeFrom: args.resumeFrom } : {}),
    onProgress: ({ tenantId, indexed, lastId }) => {
      logger.info({ tenantId, indexed, lastId }, "reindex-search: progress");
    },
  });

  logger.info(
    { provider: provider.name, indexed: result.indexed },
    "reindex-search: complete",
  );
}

main()
  .then(async () => {
    const { pool } = await import("@workspace/db");
    await pool.end();
    process.exit(0);
  })
  .catch(async (err) => {
    logger.error({ err }, "reindex-search: failed");
    try {
      const { pool } = await import("@workspace/db");
      await pool.end();
    } catch {
      // ignore pool-close errors on the failure path
    }
    process.exit(1);
  });
