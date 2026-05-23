// Periodic ledger chain verifier. Closes the M1.8 gap: §23.2 promises
// hourly window walks + weekly full walks with `ledger.chain_invalid`
// emitted on mismatch, but until M1.8 the only verification ran at boot
// and via GET /admin/ledger/verify.
//
// Design:
//   - Each scheduled run calls `verifyChainSince(now-24h)` or `verifyChain()`.
//   - On mismatch, append a `ledger.chain_invalid` event whose post-commit
//     hook (lib/alerts.ts) emits an `alert=true` stderr line for the log
//     shipper to route per §25.
//   - The verifier's own ledger writes continue the (now-broken) chain
//     forward; auditors see the mismatch at the tampered seq AND the
//     `ledger.chain_invalid` attestation that we detected it.
//   - setInterval handles are `.unref()`ed so they never keep the process
//     alive past a graceful shutdown.
//   - Crash recovery is implicit: the verifier re-checks every period; a
//     missed run cannot leave a mismatch undetected longer than `windowMs`.

import { logger } from "./logger";
import { appendLedger, verifyChain, verifyChainSince } from "./ledger";
import type { VerifyResult } from "./ledger";

export interface ChainVerifierSchedule {
  /** Rolling 24h-window walk cadence. Default 1h. */
  windowMs: number;
  /** Full-chain walk cadence. Default 7d. */
  fullMs: number;
  /** Window size for the rolling walk. Default 24h. */
  lookbackMs: number;
}

const DEFAULT_SCHEDULE: ChainVerifierSchedule = {
  windowMs: 60 * 60 * 1000,
  fullMs: 7 * 24 * 60 * 60 * 1000,
  lookbackMs: 24 * 60 * 60 * 1000,
};

async function emitInvalid(
  scope: "rolling_24h" | "full",
  r: VerifyResult,
): Promise<void> {
  // Cap the payload: full error list is in the structured log already
  // (see logger.error below); the ledger row carries only counts +
  // first few errors so it stays well under the 8KB soft cap.
  await appendLedger({
    tenantId: null,
    actor: { kind: "system", id: "chain_verifier" },
    eventType: "ledger.chain_invalid",
    subjectType: "ledger",
    subjectId: String(r.head_seq),
    payload: {
      scope,
      walked: r.walked,
      head_seq: r.head_seq,
      head_hash: r.head_hash,
      error_count: r.errors.length,
      first_errors: r.errors.slice(0, 5),
    },
  });
}

async function runOnce(
  kind: "rolling_24h" | "full",
  fn: () => Promise<VerifyResult>,
): Promise<void> {
  try {
    const r = await fn();
    if (r.ok) {
      logger.debug(
        { kind, walked: r.walked, head_seq: r.head_seq },
        "chain verifier ok",
      );
      return;
    }
    logger.error(
      {
        kind,
        walked: r.walked,
        head_seq: r.head_seq,
        error_count: r.errors.length,
        errors: r.errors,
      },
      "chain verifier detected mismatch — emitting ledger.chain_invalid",
    );
    await emitInvalid(kind, r);
  } catch (err) {
    // Verifier failures are themselves operational concerns but not chain
    // integrity events — surface as ERROR, do NOT append a chain_invalid
    // (that would muddy the security signal).
    logger.error({ err, kind }, "chain verifier run failed");
  }
}

/** Start the periodic chain verifier. Returns a stop() handle for tests. */
export function startChainVerifier(
  schedule: Partial<ChainVerifierSchedule> = {},
): () => void {
  const s = { ...DEFAULT_SCHEDULE, ...schedule };
  const intervals: ReturnType<typeof setInterval>[] = [];

  const windowTimer = setInterval(
    () => void runOnce("rolling_24h", () =>
      verifyChainSince(new Date(Date.now() - s.lookbackMs)),
    ),
    s.windowMs,
  );
  const fullTimer = setInterval(
    () => void runOnce("full", () => verifyChain()),
    s.fullMs,
  );
  intervals.push(windowTimer, fullTimer);

  // Never keep the process alive on shutdown.
  for (const t of intervals) t.unref?.();

  logger.info(
    {
      windowMs: s.windowMs,
      fullMs: s.fullMs,
      lookbackMs: s.lookbackMs,
    },
    "chain verifier scheduled",
  );

  return () => {
    for (const t of intervals) clearInterval(t);
  };
}

// Exported for direct testing without spinning up setInterval.
export const __test__ = { runOnce, emitInvalid };
