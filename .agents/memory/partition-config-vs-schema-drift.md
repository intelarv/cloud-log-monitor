---
name: Partition config vs schema drift
description: When a DDL conversion is one-way, derive runtime behavior from the DB catalog, not the env flag that requested it.
---

# Partition config must follow the catalog, not the env flag

`finding_embeddings` can be a single table (PK `finding_id`) or LIST-partitioned
by `tenant_id` (composite PK `finding_id, tenant_id`). The boot conversion is
**one-way** (single→partitioned only; going back requires `DROP TABLE` since it's
a derived cache). The embedding upsert picks its `ON CONFLICT` arbiter from this
layout.

**Rule:** the runtime "is partitioned?" switch must be reconciled against the
live catalog (`pg_partitioned_table`) after bootstrap, not left equal to the
`EMBEDDINGS_TENANT_PARTITIONING` env intent.

**Why:** a deployment once booted partitioned, then later booted with the flag
off, keeps the partitioned table (conversion never reverses). If the upsert
arbiter were driven purely by the env flag it would emit `ON CONFLICT
(finding_id)` against a composite-PK table → Postgres arbiter error at
backfill/ingest. The env flag is operator *intent*; the catalog is *truth*.

**How to apply:** any time a config switch selects a code path that must match a
schema produced by a non-reversible migration, read the actual schema and let it
win (log a warning on mismatch). Same pattern would apply to any future one-way
table-shape conversion.
