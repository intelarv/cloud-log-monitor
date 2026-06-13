// Stable workflow-id derivation for the per-finding review.
//
// Extracted into its own tiny, dependency-light module (only `node:crypto`) so
// BOTH the Temporal engine (temporal-engine.ts, which uses it as the Temporal
// start-workflow id for start-idempotency) AND the activities (review-steps.ts,
// which use it as the prefix of each step's ledger idempotency key) can import
// it without a circular dependency or pulling the heavy engine module into the
// activity path.

import { createHash } from "node:crypto";

/** Stable, collision-resistant workflow id from {tenant, finding}. Same value
 *  for a duplicate emit -> Temporal start-workflow idempotency dedupes it, and
 *  the review activities derive their per-step idempotency keys from it. */
export function workflowIdFor(tenantId: string, findingId: string): string {
  // Length-prefix the tenant segment so the encoding is unambiguous even when
  // an id contains the ":" delimiter (otherwise ("a","b:c") and ("a:b","c")
  // would both hash "a:b:c" and collide on the same workflow id).
  const h = createHash("sha256")
    .update(`${tenantId.length}:${tenantId}:${findingId}`)
    .digest("hex");
  return `review-${h.slice(0, 32)}`;
}
