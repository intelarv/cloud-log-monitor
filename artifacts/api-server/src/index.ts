import app from "./app";
import { logger } from "./lib/logger";
import { bootstrap } from "@workspace/db";
import { verifyChain } from "./lib/ledger";

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
  // Step 1: idempotent DB setup (RLS policies + findings_redacted view).
  // Safe to run every boot; CREATE OR REPLACE / DROP IF EXISTS make it so.
  logger.info("Running DB bootstrap (setup + seed-if-empty)");
  const boot = await bootstrap();
  logger.info(boot, "DB bootstrap complete");

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
