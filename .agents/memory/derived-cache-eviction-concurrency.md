---
name: Derived-cache eviction concurrency guard
description: Why eviction/pruning DELETEs over a derived cache must re-check the live protected-state predicate in the same statement.
---

# Derived-cache eviction must re-check protected state at DELETE time

When a periodic job selects rows to prune from a *derived* cache (e.g. the
`finding_embeddings` pgvector cache) based on an in-memory policy computed from a
prior SELECT, the DELETE must re-assert any "never-evict" predicate against the
live source row in the same statement — e.g.:

```sql
DELETE FROM finding_embeddings fe
USING findings f
WHERE fe.finding_id = f.id
  AND fe.finding_id IN (<selected ids>)
  AND NOT (f.severity = 'critical' AND f.status = 'open')  -- live floor re-check
```

**Why:** Postgres default isolation is READ COMMITTED. Even when SELECT + compute
+ DELETE run in one transaction, a *concurrent* transaction can commit a state
change (e.g. a finding flips to critical+open) between the SELECT snapshot and
the DELETE. Without the in-statement re-check, the stale selection would delete a
now-protected row, silently violating the hard floor. The architect flagged this
exact gap; the fix is a self-contained guard, not raising the isolation level.

**How to apply:** Any leader-locked pruning/eviction/tiering job that has a
"never touch rows matching predicate P" invariant must encode P directly in the
mutating statement (JOIN the source table), not rely solely on the pure
selection function. Add a regression test that runs the guarded DELETE
explicitly targeting a P-matching row and asserts `rowCount === 0`.
