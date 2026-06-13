---
name: Raw-evidence tiering vs ingest ref ownership
description: Why a job that ages inline raw PHI into an external WORM ref must merge with ingest's ref, not overwrite it.
---

# Raw-evidence inline→ref migration must MERGE, not overwrite

When an external raw-evidence store is active, ingest does NOT touch a legacy
finding's inline `raw_evidence` column on re-hits (its inline merge is gated on
`!externalRaw`). Instead ingest advances `raw_evidence_ref.latest` to each new
occurrence's WORM object (set-once `first` via COALESCE). So a legacy row in the
post-switch steady state can simultaneously hold a STALE inline `{first,latest}`
(pre-switch occurrences) AND an ingest-maintained ref whose `latest` is NEWER.

**Rule:** any process that migrates inline raw → external ref (e.g. the tiering
lifecycle) must MERGE, never blind-overwrite:
- inline `first` is the TRUE earliest (predates the switch; ingest's ref.first
  only knows post-switch occurrences) → it wins the `ref.first` slot.
- prefer an ingest-seated newer `ref.latest` over the stale inline latest.
- get-verify EVERY uri that ends up in the committed ref BEFORE nulling inline
  (never null the sole copy on an unverified object).
- finalize under `FOR UPDATE` + an optimistic guard (`ref.latest` unchanged
  since you read/verified it) → skip+retry if ingest advanced it concurrently.

**Why:** a naive write-inline-then-null would clobber the newer ref and orphan
the post-switch occurrence pointers — break-glass would then show a stale
latest. Orphaned WORM objects aren't PHI loss (immutable), but the pointer loss
is an audit-correctness defect.

**How to apply:** whenever you add code that moves raw evidence between tiers or
rewrites `raw_evidence_ref`, treat ingest as a concurrent writer of `.latest`
and merge. Also: no object URIs in logs OR ledger for this surface — log the
error NAME only on failure (SDK errors can embed the bucket/key URI).
