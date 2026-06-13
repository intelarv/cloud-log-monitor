import { pgTable, text, timestamp } from "drizzle-orm/pg-core";

// M12.1: per-tenant key registry (control-plane).
//
// Maps a tenant to a dedicated signing/encryption key so a single global
// secret (SESSION_SECRET) is not the sole root of trust across every tenant.
// This is CONTROL-PLANE, system-scoped metadata: it carries only a provider +
// an opaque reference, NEVER raw key material — so (a) it has no tenant RLS
// (the boot resolver must read every row to build its in-memory cache) and (b)
// it is never exposed through any API. An empty table means every tenant falls
// back to the global secret, i.e. behavior is byte-identical to pre-M12.1
// (default-inert, matching the codebase's other optional seams).
//
//   provider = 'derived'  → the per-tenant key is HKDF(global root, tenant,
//                           purpose); key_ref is unused. Gives per-tenant key
//                           separation with no extra dependency (dev model).
//   provider = 'external' → key_ref names an ENV VAR that holds the material
//                           (operator wires Vault / cloud KMS → env). The DB
//                           stores only the variable NAME, never the secret, so
//                           no key material lives at rest here (threat_model
//                           §Info Disclosure: "secrets MUST NOT be in DB").
export const tenantKmsKeysTable = pgTable("tenant_kms_keys", {
  tenantId: text("tenant_id").primaryKey(),
  // Stable id of the active key for this tenant (e.g. "tenant-key-v1").
  // Mixed into the HKDF info for 'derived' so bumping it rotates the key.
  keyId: text("key_id").notNull(),
  // "derived" | "external" (validated by isTenantKeyProvider in the resolver;
  // an unknown value is skipped at load time rather than crashing boot).
  provider: text("provider").notNull(),
  // For 'external': the NAME of the env var holding the key material. NULL for
  // 'derived'. Never the material itself.
  keyRef: text("key_ref"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type TenantKmsKey = typeof tenantKmsKeysTable.$inferSelect;
