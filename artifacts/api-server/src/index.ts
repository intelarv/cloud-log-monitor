import app from "./app";
import { logger } from "./lib/logger";
import { bootstrap } from "@workspace/db";
import { verifyChain } from "./lib/ledger";
import { startChainVerifier } from "./lib/chain-verifier";
import { backfillEmbeddings } from "./lib/search";
import { initEmbedderFromEnv } from "./lib/embedder-config";
import { hasDedicatedNotarizationSecret } from "./lib/notarization";
import { startIngestPipeline } from "./lib/ingest";
import { logBus } from "./lib/log-bus";
import { startAgentSupervisor } from "./lib/agents/supervisor";

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
  // M2: the same scheduler also drives external notarization checkpoint
  // creation + verification (5min cadence in dev).
  if (!hasDedicatedNotarizationSecret()) {
    logger.warn(
      "NOTARIZATION_SECRET is not set; falling back to SESSION_SECRET-derived dev key. " +
        "Production deployments MUST set NOTARIZATION_SECRET to a value held in a SEPARATE trust zone " +
        "(separate KMS / separate cloud account) per ARCHITECTURE.md §23.2 — co-locating the two " +
        "secrets defeats the second-half tamper-evidence guarantee.",
    );
  }
  startChainVerifier();

  // Step 4 (M3): wire the ingest pipeline to the process-wide log bus.
  // Source adapters publish `LogRecord`s; the pipeline runs Stage-1
  // detectors and produces findings + ledger entries. The in-memory bus
  // is the dev stand-in for Kafka/Redpanda/NATS per ARCHITECTURE.md §3 —
  // production swaps the bus impl without touching the pipeline.
  // No source is auto-started; POST /api/admin/ingest/replay triggers
  // the static fixture source on demand.
  startIngestPipeline(logBus);

  // Step 5 (M5): start the multi-agent supervisor. Wires the in-memory
  // review queue and arms `maybeEnqueueReviewFromLedger` (already attached
  // to appendLedger's post-commit hook in lib/ledger.ts). On every newly
  // created finding the supervisor runs Triage → Verifier and persists
  // verdicts; both steps ledger with full agent identity per
  // ARCH §7 / §24. Cost is bounded by AGENT_DAILY_TOKEN_BUDGET; concurrency
  // is bounded inside the supervisor module.
  startAgentSupervisor();

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
