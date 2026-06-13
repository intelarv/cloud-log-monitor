import { hkdfSync } from "node:crypto";
import { db, tenantKmsKeysTable } from "@workspace/db";
import { logger } from "./logger";

// ---------------------------------------------------------------------------
// Per-tenant KMS key resolver (M12.1)
// ---------------------------------------------------------------------------
//
// threat_model §EoP "Cross-tenant escalation" calls for per-tenant KMS keys so
// a single global secret is not the sole root of trust across tenants. This is
// the application-side seam: a tenant→key registry (the `tenant_kms_keys`
// control-plane table) plus a synchronous resolver the auth hot path can call.
//
// Default-inert, exactly like the embedder / raw-evidence / NER seams: with an
// empty registry (the dev + credential-free eval-gate default) every resolve
// returns null, callers fall back to the global secret, and every signature is
// byte-identical to pre-M12.1. The actual cloud-KMS provisioning + rotation
// lifecycle is operator / Terraform territory (see docs/MILESTONES.md M12.1);
// what lives here is the table, the resolver, and the wiring.
//
// Providers:
//   - "derived"  → HKDF(global root, tenant, purpose). Gives per-tenant key
//                  separation with no extra dependency (dev model).
//   - "external" → keyRef names an ENV VAR holding the material (operator wires
//                  Vault / cloud KMS → env). The DB stores only the variable
//                  NAME, never the secret, so no key material lives at rest.
// ---------------------------------------------------------------------------

export type TenantKeyProvider = "derived" | "external";

export interface TenantKeyDescriptor {
  tenantId: string;
  keyId: string;
  provider: TenantKeyProvider;
  keyRef: string | null;
}

// A per-tenant key (and the global root) must clear this length to be usable;
// shorter material is ignored and the caller falls back to the global secret.
const MIN_MATERIAL_LEN = 16;
const DERIVED_KEY_LEN = 32;

// In-memory registry cache.
//   null      → not loaded yet (boot hasn't run / a unit test) — treated
//               exactly like "no dedicated key" so the hot path never blocks.
//   empty Map → loaded, zero registered tenants.
// Either way every resolve returns null ⇒ callers use the global secret ⇒
// byte-identical to pre-M12.1 (default-inert).
let cache: Map<string, TenantKeyDescriptor> | null = null;

export function isTenantKeyProvider(s: string): s is TenantKeyProvider {
  return s === "derived" || s === "external";
}

/** Test/boot hook: install a known set of descriptors (or clear with null). */
export function setTenantKmsCache(rows: TenantKeyDescriptor[] | null): void {
  cache = rows === null ? null : new Map(rows.map((r) => [r.tenantId, r]));
}

export function resetTenantKmsForTests(): void {
  cache = null;
}

function globalRoot(): string | null {
  const s = process.env.SESSION_SECRET;
  return typeof s === "string" && s.length >= MIN_MATERIAL_LEN ? s : null;
}

/** Resolve a tenant's dedicated secret for a signing/encryption `purpose`, or
 *  null when the tenant has no dedicated key (caller MUST fall back to the
 *  global secret). Pure + synchronous: reads only the in-memory cache + env, so
 *  it is safe to call on the auth hot path. Default-inert: an unloaded or empty
 *  cache always returns null. */
export function resolveTenantSecret(
  tenantId: string,
  purpose: string,
): string | null {
  if (!cache) return null;
  const d = cache.get(tenantId);
  if (!d) return null;
  switch (d.provider) {
    case "derived": {
      const root = globalRoot();
      if (!root) return null;
      // HKDF gives each tenant a distinct key from the shared root, with the
      // tenant as salt and the keyId + purpose in info so the same root cannot
      // produce a colliding key across tenants or purposes. Bumping keyId
      // rotates the derived key.
      const out = hkdfSync(
        "sha256",
        root,
        tenantId,
        `phia-tenant-kms:${d.keyId}:${purpose}`,
        DERIVED_KEY_LEN,
      );
      return Buffer.from(out).toString("base64");
    }
    case "external": {
      if (!d.keyRef) return null;
      const material = process.env[d.keyRef];
      return typeof material === "string" && material.length >= MIN_MATERIAL_LEN
        ? material
        : null;
    }
    default:
      return null;
  }
}

/** True iff `tenantId` has a dedicated key registered. Callers may use this to
 *  ledger/log that a per-tenant key was in force for an action. */
export function hasTenantKey(tenantId: string): boolean {
  return !!cache && cache.has(tenantId);
}

/** Load the registry from the DB into the in-memory cache. Called once at boot
 *  AFTER bootstrap() has ensured the table exists. A row with an unknown
 *  provider is skipped (logged) rather than throwing, so one malformed row
 *  cannot take boot down. Returns the count of usable descriptors loaded. */
export async function loadTenantKmsCacheFromDb(): Promise<number> {
  const rows = await db.select().from(tenantKmsKeysTable);
  const usable: TenantKeyDescriptor[] = [];
  for (const r of rows) {
    if (!isTenantKeyProvider(r.provider)) {
      logger.warn(
        { tenantId: r.tenantId, provider: r.provider },
        "tenant_kms_keys: skipping row with unknown provider",
      );
      continue;
    }
    usable.push({
      tenantId: r.tenantId,
      keyId: r.keyId,
      provider: r.provider,
      keyRef: r.keyRef,
    });
  }
  setTenantKmsCache(usable);
  if (usable.length > 0) {
    logger.info(
      { count: usable.length },
      "Per-tenant KMS key registry loaded (M12.1)",
    );
  }
  return usable.length;
}
