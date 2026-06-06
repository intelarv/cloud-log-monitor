---
name: A2A auth-layer ledgering posture
description: Which A2A request-rejection layers write to the immutable ledger vs log-only, and why they differ.
---

# A2A auth-layer ledgering posture

The A2A agent plane has a defense-in-depth ladder of request gates (outermost
first): mTLS transport check → shared-secret bearer → caller-identity JWT + ABAC
scope. Their rejection behavior is **deliberately not uniform**:

- **Shared-secret (401) and caller-identity/scope (401/403)**: `logger.warn` only,
  **NOT** ledgered.
- **mTLS transport (403)**: 403 **and** a system-scoped `a2a.transport_rejected`
  ledger entry (tenantId null, actor `{kind:"system",id:"a2a_transport"}`, payload
  = fixed agent route + static reason only — never request headers/body).

**Why the split:** The general posture is log-only for transport/auth-handshake
failures, because an unauthenticated network probe could otherwise amplify writes
to the append-only, advisory-lock-serialized ledger (a DoS vector against the
system's most precious asset — threat_model §DoS). The mTLS layer is the
exception **only** because that layer's requirement explicitly called for
non-repudiation ("403 + ledger on failure"), and the amplification risk is
judged bounded: the
A2A routes are loopback-only behind ingress (not in the shared proxy path table),
the write is fire-and-forget AFTER the 403 (cannot delay/roll back the refusal),
and it is inert unless `A2A_REQUIRE_MTLS` is set.

**How to apply:** If you add a new A2A rejection path, default to log-only to stay
consistent with the shared-secret/scope layers unless there is an explicit
non-repudiation requirement; if you do ledger it, keep the payload free of
attacker-influenced data and fire it after responding. Any new ledger `eventType`
literal must be written **inline at the `eventType:` call site** (not via a const
reference) or `event-type-coverage.test.ts`'s regex scanner won't see it, and it
must be registered in `ALERT_RULES` or `NOT_ALERTABLE`.
