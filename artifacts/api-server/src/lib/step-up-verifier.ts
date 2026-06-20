import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { and, eq, isNull, lt, or } from "drizzle-orm";
import { stepUpFactorsTable } from "@workspace/db";
import { withTenant } from "./db-context";
import { resolveTenantSecret } from "./tenant-kms";
import { verifyStepUpToken } from "./auth";
import {
  generateSecret,
  otpauthUri,
  verifyTotp,
} from "./totp";

// ---------------------------------------------------------------------------
// Step-up second-factor verifier seam (STEP_UP_PROVIDER)
// ---------------------------------------------------------------------------
//
// The step-up flow (the second factor presented AFTER a session is already
// established, gating raw-PHI break-glass + remediation confirm) is now behind
// a provider seam, exactly like the embedder / NER / raw-evidence / LLM seams:
//
//   - STEP_UP_PROVIDER=dev   (DEFAULT) → the existing dev shared-token check
//                            (`verifyStepUpToken`, STEP_UP_DEV_TOKEN). No DB
//                            read, no enrollment, byte-identical to before.
//                            This is what the credential-free eval gate runs.
//   - STEP_UP_PROVIDER=totp           → RFC 6238 TOTP. The analyst enrolls an
//                            authenticator app once; every step-up then proves
//                            possession of a fresh 6-digit code. The shared
//                            secret is encrypted at rest (AES-256-GCM, per-tenant
//                            key) and a per-step replay guard prevents reuse.
//
// Default-inert: with the default dev provider nothing here touches the DB or
// loads any new code path, so the offline eval gate stays byte-identical.

const ISSUER = "PHI-Audit";
const ENC_VERSION = "v1";
const ENC_PURPOSE = "stepup-totp";
const AES_KEY_LEN = 32; // AES-256
const GCM_IV_LEN = 12;

export type StepUpProvider = "dev" | "totp";

/** Resolve the configured provider. Unknown / unset ⇒ "dev" (default-inert). */
export function stepUpProvider(): StepUpProvider {
  return process.env.STEP_UP_PROVIDER === "totp" ? "totp" : "dev";
}

// --- at-rest encryption of the TOTP shared secret --------------------------

function globalSecret(): string {
  const s = process.env.SESSION_SECRET;
  if (typeof s !== "string" || s.length < 16) {
    throw new Error("SESSION_SECRET must be set and at least 16 characters long.");
  }
  return s;
}

/** Derive the AES-256 key for a tenant's TOTP secrets. Uses the tenant's
 *  dedicated KMS key when one is registered (M12.1), otherwise HKDF over the
 *  global SESSION_SECRET — same fallback posture as the cookie-signing key. */
function encKey(tenantId: string): Buffer {
  const material = resolveTenantSecret(tenantId, ENC_PURPOSE) ?? globalSecret();
  return Buffer.from(
    hkdfSync("sha256", material, tenantId, `phia-${ENC_PURPOSE}-enc`, AES_KEY_LEN),
  );
}

/** AES-256-GCM encrypt the base32 secret → `v1.<iv>.<tag>.<ct>` (base64url). */
function encryptSecret(tenantId: string, plaintext: string): string {
  const iv = randomBytes(GCM_IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", encKey(tenantId), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    ENC_VERSION,
    iv.toString("base64url"),
    tag.toString("base64url"),
    ct.toString("base64url"),
  ].join(".");
}

/** Inverse of encryptSecret. Throws on a malformed envelope or auth-tag
 *  mismatch (tamper / wrong key) — callers treat any throw as "no usable
 *  factor" and refuse the step-up. */
function decryptSecret(tenantId: string, envelope: string): string {
  const parts = envelope.split(".");
  if (parts.length !== 4 || parts[0] !== ENC_VERSION) {
    throw new Error("malformed step-up secret envelope");
  }
  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const ct = Buffer.from(parts[3], "base64url");
  const decipher = createDecipheriv("aes-256-gcm", encKey(tenantId), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

// --- enrollment ------------------------------------------------------------

export interface EnrollmentProvisionResult {
  /** The base32 secret, shown once for manual key entry. */
  secret: string;
  /** otpauth:// URI to render as the enrollment QR code. */
  otpauthUri: string;
}

/** Provision (or re-provision) a pending TOTP secret for a user. Overwrites any
 *  existing factor and resets it to UNVERIFIED — the user must confirm with a
 *  live code before it can satisfy a step-up. */
export async function provisionTotpSecret(
  tenantId: string,
  userId: string,
): Promise<EnrollmentProvisionResult> {
  const secret = generateSecret();
  const secretEnc = encryptSecret(tenantId, secret);
  await withTenant(tenantId, async (tx) => {
    await tx
      .insert(stepUpFactorsTable)
      .values({
        tenantId,
        userId,
        type: "totp",
        secretEnc,
        verifiedAt: null,
        lastUsedStep: null,
      })
      .onConflictDoUpdate({
        target: [stepUpFactorsTable.tenantId, stepUpFactorsTable.userId],
        set: {
          type: "totp",
          secretEnc,
          verifiedAt: null,
          lastUsedStep: null,
          updatedAt: new Date(),
        },
      });
  });
  return {
    secret,
    otpauthUri: otpauthUri({ secretBase32: secret, account: userId, issuer: ISSUER }),
  };
}

/** Confirm a pending enrollment with a live code. On success the factor becomes
 *  VERIFIED and the used step is recorded (so the enrollment code cannot be
 *  immediately replayed as a step-up). Returns false if no enrollment is in
 *  progress or the code does not match. */
export async function confirmTotpEnrollment(
  tenantId: string,
  userId: string,
  code: string,
): Promise<boolean> {
  return withTenant(tenantId, async (tx) => {
    const [row] = await tx
      .select()
      .from(stepUpFactorsTable)
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
        ),
      );
    if (!row) return false;
    let secret: string;
    try {
      secret = decryptSecret(tenantId, row.secretEnc);
    } catch {
      return false;
    }
    const matched = verifyTotp(secret, code);
    if (matched === null) return false;
    // Same CAS as the step-up replay guard: only confirm if this step advances
    // the guard, so two parallel confirms with the same code cannot both win.
    const confirmed = await tx
      .update(stepUpFactorsTable)
      .set({ verifiedAt: new Date(), lastUsedStep: matched, updatedAt: new Date() })
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
          or(
            isNull(stepUpFactorsTable.lastUsedStep),
            lt(stepUpFactorsTable.lastUsedStep, matched),
          ),
        ),
      )
      .returning({ userId: stepUpFactorsTable.userId });
    return confirmed.length > 0;
  });
}

export interface FactorStatus {
  enrolled: boolean;
  verified: boolean;
}

/** Enrollment status for the dashboard panel: whether a factor exists and
 *  whether it has been confirmed. */
export async function getFactorStatus(
  tenantId: string,
  userId: string,
): Promise<FactorStatus> {
  return withTenant(tenantId, async (tx) => {
    const [row] = await tx
      .select()
      .from(stepUpFactorsTable)
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
        ),
      );
    return { enrolled: !!row, verified: !!row?.verifiedAt };
  });
}

// --- verifier seam ---------------------------------------------------------

export interface StepUpVerifyCtx {
  tenantId: string;
  sub: string;
  token: string;
}

export interface StepUpVerifier {
  readonly kind: StepUpProvider;
  verify(ctx: StepUpVerifyCtx): Promise<boolean>;
}

/** Dev shared-token verifier — the default. Ignores tenant/sub and compares the
 *  supplied token against STEP_UP_DEV_TOKEN in constant time, exactly as before. */
const devVerifier: StepUpVerifier = {
  kind: "dev",
  verify: async ({ token }) => verifyStepUpToken(token),
};

/** TOTP verifier. Looks up the user's VERIFIED factor, decrypts the secret,
 *  verifies the code with ±1 step skew, and enforces a per-step replay guard
 *  (a code from an already-used step or earlier is refused). */
const totpVerifier: StepUpVerifier = {
  kind: "totp",
  verify: async ({ tenantId, sub, token }) =>
    withTenant(tenantId, async (tx) => {
      const [row] = await tx
        .select()
        .from(stepUpFactorsTable)
        .where(
          and(
            eq(stepUpFactorsTable.tenantId, tenantId),
            eq(stepUpFactorsTable.userId, sub),
          ),
        );
      if (!row || !row.verifiedAt) return false;
      let secret: string;
      try {
        secret = decryptSecret(tenantId, row.secretEnc);
      } catch {
        return false;
      }
      const matched = verifyTotp(secret, token);
      if (matched === null) return false;
      // Replay guard: a code is single-use per step. The advance is done as a
      // single compare-and-swap UPDATE (`last_used_step IS NULL OR < matched`)
      // and we treat "0 rows updated" as a replay refusal, so two concurrent
      // requests carrying the same valid code cannot both succeed (the read-
      // then-update form had a TOCTOU race).
      const advanced = await tx
        .update(stepUpFactorsTable)
        .set({ lastUsedStep: matched, updatedAt: new Date() })
        .where(
          and(
            eq(stepUpFactorsTable.tenantId, tenantId),
            eq(stepUpFactorsTable.userId, sub),
            or(
              isNull(stepUpFactorsTable.lastUsedStep),
              lt(stepUpFactorsTable.lastUsedStep, matched),
            ),
          ),
        )
        .returning({ userId: stepUpFactorsTable.userId });
      return advanced.length > 0;
    }),
};

/** Resolve the active verifier from STEP_UP_PROVIDER. */
export function getStepUpVerifier(): StepUpVerifier {
  return stepUpProvider() === "totp" ? totpVerifier : devVerifier;
}

// Exposed for unit tests of the at-rest crypto round-trip.
export const __testing = { encryptSecret, decryptSecret };
