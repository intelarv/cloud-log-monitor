---
name: Postgres rejects NUL bytes in text
description: NUL-joined in-memory keys can't be persisted to Postgres text columns; encode them first.
---

Postgres `text`/`varchar` columns reject the NUL byte (`0x00`): an insert fails
at runtime with `error: invalid byte sequence for encoding "UTF8": 0x00`. The
error surfaces only via the driver's underlying `cause` — Drizzle wraps it as a
generic `Error: Failed query: ...`, so logging `err.name` alone hides it; log
`(err as {cause?}).cause` to see the real message.

**Why this bites here:** several in-memory grouping/identity keys are joined on
NUL (`\u0000`) precisely because NUL can't appear in normal text — making them
collision-free. That same property makes them unstorable. (e.g. memory-eviction
`groupKey()` is NUL-joined.)

**How to apply:** before persisting any NUL-joined key to a text column (or using
it as an `ON CONFLICT` target), encode it NUL-free and collision-free — base64 of
the UTF-8 bytes works (`Buffer.from(key, "utf8").toString("base64")`). Use the
SAME encoded form for both the upsert value and any existing-row lookup map so
the conflict key matches. Keep the human-readable components in their own columns;
the encoded key only needs to be stable, not readable. A hash (sha256) only joined
for hashing is fine — hashing doesn't store the NUL.
