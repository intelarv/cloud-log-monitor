import app from "./app";
import { logger } from "./lib/logger";
import { bootstrap } from "@workspace/db";
import { verifyChain } from "./lib/ledger";
import { startChainVerifier } from "./lib/chain-verifier";
import { backfillEmbeddings } from "./lib/search";
import { initEmbedderFromEnv } from "./lib/embedder-config";

const rawPort = process.env["PORT"];
if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}
const port = Number(rawPort);
if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

async function main(): Promise<void> {
  // Step 0: resolve the embedder from env (provider, model, dim) BEFORE
  // bootstrap so the DB column dim matches what the embedder will produce.
  // See embedder-config.ts for precedence (EMBEDDING_PROVIDER > DEPLOYMENT_TARGET).
  const { config: embedderConfig } = initEmbedderFromEnv();

  // Step 1: idempotent DB setup (RLS policies + findings_redacted view).
  // Safe to run every boot; CREATE OR REPLACE / DROP IF EXISTS make it so.
  // The embedding-column dim is passed through; if a pre-existing column has
  // a different dim, bootstrap throws with a clear migration message.
  logger.info("Running DB bootstrap (setup + seed-if-empty)");
  const boot = await bootstrap({ embeddingDim: embedderConfig.dim });
  logger.info(boot, "DB bootstrap complete");

  // Step 1.5 (M1): backfill embeddings for any finding without one (or
  // re-embed when the embedder version has changed). Idempotent; cheap when
  // already converged. Uses the embedder registered in step 0.
  const emb = await backfillEmbeddings();
  logger.info(emb, "Embedding backfill complete");

  // Step 2: chain verification. The system's tamper-evidence claim depends
  // on this; if the chain is broken at boot, we refuse to start.
  // See ARCHITECTURE.md §23.2.
  const v = await verifyChain();
  logger.info(
    {
      ok: v.ok,
      walked: v.walked,
      head_seq: v.head_seq,
      head_hash_short: v.head_hash.slice(0, 16),
    },
    "Ledger chain verification",
  );
  if (!v.ok) {
    logger.error({ errors: v.errors }, "Ledger chain INVALID — refusing to start");
    process.exit(2);
  }

  // Step 3 (M1.8): start the periodic chain verifier — hourly 24h-window
  // walk + weekly full walk. On mismatch it appends `ledger.chain_invalid`
  // whose post-commit alert hook routes via §25. See ARCHITECTURE.md §23.2.
  startChainVerifier();

  app.listen(port, (err) => {
    if (err) {
      logger.error({ err }, "Error listening on port");
      process.exit(1);
    }
    logger.info({ port }, "Server listening");
  });
}

main().catch((err) => {
  logger.error({ err }, "Fatal startup error");
  process.exit(1);
});
