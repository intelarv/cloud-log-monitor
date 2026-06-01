---
name: Cloud-pluggable subsystem seams
description: Convention for adding a cloud-pluggable backend (embedder, lexical search, raw-evidence store) behind a factory seam in the PHI-audit api-server
---

# Cloud-pluggable subsystem seams

The api-server has a repeated pattern for subsystems that have a dev-local default
and one or more cloud backends: embedder (`embedder-config.ts` + `cloud-embedders.ts`),
lexical search (`search-config.ts` + `cloud-search.ts`), raw-evidence store
(`raw-evidence-store.ts` + `cloud-raw-evidence-stores.ts`). New cloud-pluggable work
should mirror this same shape: an interface + a dev default class + a config/factory
that reads one explicit `*_PROVIDER` env + a registry (`get`/`getOrNull`/`set`/`reset`/`initFromEnv`),
and cloud impls behind **lazy** SDK imports with thin mockable clients.

**Rule — no `DEPLOYMENT_TARGET` shortcut for anything that needs an explicit endpoint
or moves PHI.** The embedder *does* honor a `DEPLOYMENT_TARGET=aws|gcp|azure` shortcut
(it can pick a sensible default model). But lexical search (OpenSearch) and the
raw-evidence WORM store deliberately do NOT: they require an explicit endpoint /
bucket / container, so a bare cloud target must never silently flip the lexical leg
off Postgres or start writing raw PHI to object storage. Provider selection for those
is `*_PROVIDER`-only.

**Why:** moving raw PHI or pointing at an external index is a high-consequence,
operator-explicit decision; a convenience shortcut that does it implicitly is a
foot-gun for a HIPAA system.

**How to apply:** when adding the next cloud-pluggable subsystem, copy the
search/raw-evidence config+factory+registry structure, gate selection on an explicit
`*_PROVIDER`, lazy-load the SDK, and require the explicit resource (endpoint/bucket)
rather than inferring it from a cloud target.

## Related gotcha — honest "unresolved" vs "absent"
For external WORM raw-evidence, a failed object write at ingest is non-fatal: the
finding commits with `raw_evidence_ref` NULL. The break-glass read path must surface
an explicit `raw_unresolved` signal in EVERY non-resolution case — including the
case where an external store is configured but both inline raw and the ref are NULL
(failed ingest write) — because a bare `raw_evidence: null` is indistinguishable from
a finding that genuinely has no raw evidence.
