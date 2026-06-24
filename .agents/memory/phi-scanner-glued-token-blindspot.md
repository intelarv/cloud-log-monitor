---
name: PHI scanner word-boundary blind spot
description: Why untrusted free-form failure/error text must use a static constant, not a PHI scan, before landing in a tenant-visible column.
---

# PHI scanner has word-boundary blind spots — don't use it as the sole guard on glued untrusted text

The deterministic PHI/secret scanner (`scanForPhi`, used by `validateLedgerSafeText`)
matches on word/token boundaries. A sensitive token glued into surrounding text with
no boundary — e.g. an `Error.name` like `FailureForSSN_123-45-6789` — slips past it,
so the scan returns "safe" and the raw string would be persisted verbatim.

**Rule:** when a string is both (a) fully attacker/executor-controlled and (b) free-form
(an error name/message, an arbitrary "reason"), do NOT rely on a PHI scan to make it safe
for a tenant-visible / DB / API / UI sink. Emit a **fixed static constant** instead
(e.g. `"executor_threw"`). Reserve the scan-and-redact path (truncate → `validateLedgerSafeText`
→ replace-on-fail) for text that is at least semi-structured or where a constant would
lose too much operator value — and accept that the scan is best-effort, not a guarantee.

**Why:** `RemediationExecutor` failure handling. The declared `{ok:false, reason}` path
is scanned+bounded (operators want the reason), but the thrown path was reduced to a
static constant precisely because `Error.name`/message are executor-authored and a glued
SSN evaded the scanner. The richer diagnostics belong in the executor's own trusted logs,
never in the shared `execution_error` column.

**How to apply:** any new code that copies executor/agent/log-derived free text into a
durable, tenant-readable field. If you can't structure it, constant-ize it.
