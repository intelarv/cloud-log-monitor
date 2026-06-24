import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { and, eq, isNotNull, isNull, lt, or } from "drizzle-orm";
import { stepUpFactorsTable } from "@workspace/db";
import { withTenant } from "./db-context";
import { resolveTenantSecret } from "./tenant-kms";
import { verifyStepUpToken } from "./auth";
import {
  generateSecret,
  otpauthUri,
  verifyTotp,
} from "./totp";
// WebAuthn is the only step-up provider whose verification logic lives in a
// separate module (`./webauthn`). It is lazy-imported inside the webauthn-only
// functions/verifier branch below (never at module top level) so the default
// dev provider — and the TOTP provider, and the credential-free eval gate —
// never even parse it. Types are erased at compile time, so importing them is
// free and does not pull the module into the runtime graph.
import type { RegistrationInput, WebauthnPolicy } from "./webauthn";
// OIDC verification logic lives in `./oidc`, lazy-imported on the oidc code path
// only (same posture as `./webauthn`): the dev/TOTP/WebAuthn providers and the
// credential-free eval gate never parse it. Types are erased at compile time.
import type { OidcPolicy } from "./oidc";

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
//   - STEP_UP_PROVIDER=webauthn       → WebAuthn / FIDO2 (passkeys, security keys,
//                            platform authenticators). The analyst registers a
//                            credential once (`lib/webauthn.ts` does the hand-
//                            rolled ceremony verification, no SDK); every step-up
//                            then proves possession of the private key by signing
//                            a server-issued, single-use challenge. The credential
//                            (public key only) is encrypted at rest under the same
//                            per-tenant key and the signature counter is the
//                            clone-detection replay guard. Requires WEBAUTHN_RP_ID
//                            + WEBAUTHN_ORIGIN.
//
// Default-inert: with the default dev provider nothing here touches the DB or
// loads any new code path, so the offline eval gate stays byte-identical.

const ISSUER = "PHI-Audit";
const ENC_VERSION = "v1";
const ENC_PURPOSE = "stepup-totp";
const WEBAUTHN_ENC_PURPOSE = "stepup-webauthn";
const OIDC_ENC_PURPOSE = "stepup-oidc";
const AES_KEY_LEN = 32; // AES-256
const GCM_IV_LEN = 12;
const WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 min to complete a ceremony
// The OIDC flow is a browser redirect round-trip through the IdP login page, so
// it gets a more generous window than the local WebAuthn ceremony.
const OIDC_CHALLENGE_TTL_MS = 10 * 60 * 1000; // 10 min to complete the redirect

export type StepUpProvider = "dev" | "totp" | "webauthn" | "oidc";

/** Resolve the configured provider. Unknown / unset ⇒ "dev" (default-inert). */
export function stepUpProvider(): StepUpProvider {
  const p = process.env.STEP_UP_PROVIDER;
  if (p === "totp") return "totp";
  if (p === "webauthn") return "webauthn";
  if (p === "oidc") return "oidc";
  return "dev";
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
function encKey(tenantId: string, purpose: string = ENC_PURPOSE): Buffer {
  const material = resolveTenantSecret(tenantId, purpose) ?? globalSecret();
  return Buffer.from(
    hkdfSync("sha256", material, tenantId, `phia-${purpose}-enc`, AES_KEY_LEN),
  );
}

/** AES-256-GCM encrypt the base32 secret → `v1.<iv>.<tag>.<ct>` (base64url).
 *  `purpose` domain-separates the per-factor key (TOTP vs WebAuthn). */
function encryptSecret(
  tenantId: string,
  plaintext: string,
  purpose: string = ENC_PURPOSE,
): string {
  const iv = randomBytes(GCM_IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", encKey(tenantId, purpose), iv);
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
function decryptSecret(
  tenantId: string,
  envelope: string,
  purpose: string = ENC_PURPOSE,
): string {
  const parts = envelope.split(".");
  if (parts.length !== 4 || parts[0] !== ENC_VERSION) {
    throw new Error("malformed step-up secret envelope");
  }
  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const ct = Buffer.from(parts[3], "base64url");
  const decipher = createDecipheriv("aes-256-gcm", encKey(tenantId, purpose), iv);
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

// --- backup / recovery codes (M29) -----------------------------------------
//
// A non-dev step-up factor (authenticator app / passkey / federated IdP) can be
// lost (phone wiped, security key misplaced, IdP account locked). Backup codes
// are the account-recovery path: a one-time-generated set of single-use codes,
// each of which satisfies a step-up exactly once. They live in the existing
// row's `recovery_enc` column as an AES-256-GCM-encrypted JSON envelope
// (domain-separated key, RECOVERY_ENC_PURPOSE) — only a keyed HMAC of each code
// is stored, never the plaintext, so a DB read cannot recover a usable code.
// Consumption is a compare-and-swap on the exact prior envelope, exactly like
// the WebAuthn / OIDC single-use guards, so a code cannot be redeemed twice.

const RECOVERY_ENC_PURPOSE = "stepup-recovery";
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_BYTES = 8; // 8 chars of unambiguous base32 entropy per code

interface RecoveryEntry {
  /** Keyed HMAC (hex) of the plaintext code. Never the code itself. */
  hash: string;
  /** ISO timestamp when the code was redeemed, or null if still valid. */
  consumedAt: string | null;
}

interface RecoveryEnvelope {
  codes: RecoveryEntry[];
}

/** Keyed HMAC of a recovery code under a tenant-domain-separated key. Derived
 *  from the same per-tenant material as the AES envelope but on its own HKDF
 *  info label, so the MAC key is independent of the encryption key. */
function recoveryCodeHash(tenantId: string, code: string): string {
  const material =
    resolveTenantSecret(tenantId, RECOVERY_ENC_PURPOSE) ?? globalSecret();
  const key = Buffer.from(
    hkdfSync("sha256", material, tenantId, `phia-${RECOVERY_ENC_PURPOSE}-hmac`, 32),
  );
  return createHmac("sha256", key).update(code, "utf8").digest("hex");
}

/** Generate a human-friendly single-use code: unambiguous base32 (no I/L/O/0/1/U),
 *  two dash-separated groups for readability. */
function generateRecoveryCodePlaintext(): string {
  const ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
  const raw = randomBytes(RECOVERY_CODE_BYTES);
  let out = "";
  for (const b of raw) out += ALPHABET[b % ALPHABET.length];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

function readRecoveryEnvelope(tenantId: string, enc: string): RecoveryEnvelope {
  const parsed = JSON.parse(
    decryptSecret(tenantId, enc, RECOVERY_ENC_PURPOSE),
  ) as RecoveryEnvelope;
  if (!parsed || !Array.isArray(parsed.codes)) {
    throw new Error("malformed recovery envelope");
  }
  return parsed;
}

function writeRecoveryEnvelope(tenantId: string, env: RecoveryEnvelope): string {
  return encryptSecret(tenantId, JSON.stringify(env), RECOVERY_ENC_PURPOSE);
}

export interface RecoveryGenerateResult {
  /** Plaintext codes, shown to the user exactly once. */
  codes: string[];
}

/** Generate (or regenerate) a fresh set of backup codes. Requires an already-
 *  VERIFIED factor (you cannot mint recovery codes for an account that has no
 *  working second factor). Overwrites any prior set — old codes stop working.
 *  Returns the plaintext codes once; only their HMACs are persisted. Returns
 *  null if the user has no verified factor. */
export async function generateRecoveryCodes(
  tenantId: string,
  userId: string,
): Promise<RecoveryGenerateResult | null> {
  const plaintext = Array.from({ length: RECOVERY_CODE_COUNT }, () =>
    generateRecoveryCodePlaintext(),
  );
  const enc = writeRecoveryEnvelope(tenantId, {
    codes: plaintext.map((c) => ({
      hash: recoveryCodeHash(tenantId, c),
      consumedAt: null,
    })),
  });
  return withTenant(tenantId, async (tx) => {
    const updated = await tx
      .update(stepUpFactorsTable)
      .set({ recoveryEnc: enc, updatedAt: new Date() })
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
          isNotNull(stepUpFactorsTable.verifiedAt),
        ),
      )
      .returning({ userId: stepUpFactorsTable.userId });
    if (updated.length === 0) return null;
    return { codes: plaintext };
  });
}

export interface RecoveryStatus {
  /** A backup-code set has been generated for this account. */
  enabled: boolean;
  /** Count of still-unconsumed codes. */
  remaining: number;
}

/** Recovery-code status for the dashboard panel. */
export async function recoveryStatus(
  tenantId: string,
  userId: string,
): Promise<RecoveryStatus> {
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
    if (!row || !row.recoveryEnc) return { enabled: false, remaining: 0 };
    let env: RecoveryEnvelope;
    try {
      env = readRecoveryEnvelope(tenantId, row.recoveryEnc);
    } catch {
      return { enabled: false, remaining: 0 };
    }
    return {
      enabled: true,
      remaining: env.codes.filter((c) => !c.consumedAt).length,
    };
  });
}

/** Redeem a single backup code as a step-up second factor. Requires a VERIFIED
 *  factor with a generated code set. Marks the matched code consumed via a CAS
 *  on the exact prior envelope, so a code is single-use even under concurrent
 *  submissions. Returns false on no match / already-consumed / no code set. */
export async function consumeRecoveryCode(
  tenantId: string,
  userId: string,
  code: string,
): Promise<boolean> {
  const candidate = Buffer.from(recoveryCodeHash(tenantId, code), "hex");
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
    if (!row || !row.verifiedAt || !row.recoveryEnc) return false;
    let env: RecoveryEnvelope;
    try {
      env = readRecoveryEnvelope(tenantId, row.recoveryEnc);
    } catch {
      return false;
    }
    let matchedIdx = -1;
    for (let i = 0; i < env.codes.length; i++) {
      const e = env.codes[i]!;
      if (e.consumedAt) continue;
      const h = Buffer.from(e.hash, "hex");
      if (h.length === candidate.length && timingSafeEqual(h, candidate)) {
        matchedIdx = i;
        break;
      }
    }
    if (matchedIdx < 0) return false;
    const nextEnc = writeRecoveryEnvelope(tenantId, {
      codes: env.codes.map((e, i) =>
        i === matchedIdx ? { ...e, consumedAt: new Date().toISOString() } : e,
      ),
    });
    const advanced = await tx
      .update(stepUpFactorsTable)
      .set({ recoveryEnc: nextEnc, updatedAt: new Date() })
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
          eq(stepUpFactorsTable.recoveryEnc, row.recoveryEnc),
        ),
      )
      .returning({ userId: stepUpFactorsTable.userId });
    return advanced.length > 0;
  });
}

/** Remove the user's enrolled second factor entirely (and its recovery codes).
 *  Used for "lost my device, start over" — deletes the row so the user can
 *  re-enroll from scratch. Returns false if there was nothing to remove. */
export async function removeFactor(
  tenantId: string,
  userId: string,
): Promise<boolean> {
  return withTenant(tenantId, async (tx) => {
    const deleted = await tx
      .delete(stepUpFactorsTable)
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
        ),
      )
      .returning({ userId: stepUpFactorsTable.userId });
    return deleted.length > 0;
  });
}

// --- WebAuthn enrollment + step-up -----------------------------------------
//
// The WebAuthn credential record + the pending ceremony challenge live together
// in the existing `secret_enc` column as an AES-256-GCM-encrypted JSON envelope
// (domain-separated key, WEBAUTHN_ENC_PURPOSE) — no schema migration, the same
// at-rest protection as the TOTP secret. `last_used_step` (re)used as the
// authenticator signature counter (clone-detection replay guard). The pending
// challenge is single-use: a successful assertion clears it via a compare-and-
// swap on the exact prior envelope value, so a captured assertion cannot be
// replayed and two concurrent verifies cannot both win.

interface WebauthnEnvelope {
  credential?: { credentialId: string; publicKeySpki: string; alg: number };
  pending?: { challenge: string; exp: number };
}

/** Resolve + validate the relying-party policy from the environment. Only ever
 *  called on the webauthn code path, so the dev/eval-gate default never reads it. */
function webauthnPolicy(): WebauthnPolicy & { rpName: string } {
  const rpId = process.env.WEBAUTHN_RP_ID;
  const originEnv = process.env.WEBAUTHN_ORIGIN;
  if (!rpId || !originEnv) {
    throw new Error(
      "WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN must be set when STEP_UP_PROVIDER=webauthn",
    );
  }
  const origins = originEnv
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (origins.length === 0) {
    throw new Error("WEBAUTHN_ORIGIN must list at least one origin");
  }
  return { rpId, origins, rpName: process.env.WEBAUTHN_RP_NAME ?? ISSUER };
}

function readEnvelope(tenantId: string, raw: string): WebauthnEnvelope {
  return JSON.parse(decryptSecret(tenantId, raw, WEBAUTHN_ENC_PURPOSE)) as WebauthnEnvelope;
}

function writeEnvelope(tenantId: string, env: WebauthnEnvelope): string {
  return encryptSecret(tenantId, JSON.stringify(env), WEBAUTHN_ENC_PURPOSE);
}

export interface WebauthnRegistrationOptions {
  challenge: string; // base64url
  rpId: string;
  rpName: string;
  /** The WebAuthn user handle the browser stores (base64url of the user id). */
  userIdB64url: string;
  userName: string;
}

/** Begin (or restart) WebAuthn registration: issue a fresh challenge and reset
 *  the factor to UNVERIFIED. The client passes these options to
 *  navigator.credentials.create(). */
export async function beginWebauthnRegistration(
  tenantId: string,
  userId: string,
): Promise<WebauthnRegistrationOptions> {
  const policy = webauthnPolicy();
  const { randomChallenge } = await import("./webauthn");
  const challenge = randomChallenge();
  const secretEnc = writeEnvelope(tenantId, {
    pending: { challenge, exp: Date.now() + WEBAUTHN_CHALLENGE_TTL_MS },
  });
  await withTenant(tenantId, async (tx) => {
    await tx
      .insert(stepUpFactorsTable)
      .values({
        tenantId,
        userId,
        type: "webauthn",
        secretEnc,
        verifiedAt: null,
        lastUsedStep: null,
      })
      .onConflictDoUpdate({
        target: [stepUpFactorsTable.tenantId, stepUpFactorsTable.userId],
        set: {
          type: "webauthn",
          secretEnc,
          verifiedAt: null,
          lastUsedStep: null,
          updatedAt: new Date(),
        },
      });
  });
  return {
    challenge,
    rpId: policy.rpId,
    rpName: policy.rpName,
    userIdB64url: Buffer.from(userId, "utf8").toString("base64url"),
    userName: userId,
  };
}

/** Finish registration: verify the attestation ceremony against the pending
 *  challenge and persist the credential as VERIFIED. Returns false if there is
 *  no pending registration, it has expired, or verification fails. */
export async function finishWebauthnRegistration(
  tenantId: string,
  userId: string,
  reg: Omit<RegistrationInput, "expectedChallenge">,
): Promise<boolean> {
  const policy = webauthnPolicy();
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
    let env: WebauthnEnvelope;
    try {
      env = readEnvelope(tenantId, row.secretEnc);
    } catch {
      return false;
    }
    if (!env.pending || env.pending.exp < Date.now()) return false;
    const { verifyRegistration } = await import("./webauthn");
    const cred = verifyRegistration(
      { ...reg, expectedChallenge: env.pending.challenge },
      policy,
    );
    if (!cred) return false;
    const nextEnc = writeEnvelope(tenantId, {
      credential: {
        credentialId: cred.credentialId,
        publicKeySpki: cred.publicKeySpki,
        alg: cred.alg,
      },
    });
    // CAS on the exact prior envelope so a replayed/concurrent finish can't
    // double-register.
    const done = await tx
      .update(stepUpFactorsTable)
      .set({
        secretEnc: nextEnc,
        verifiedAt: new Date(),
        lastUsedStep: cred.signCount,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
          eq(stepUpFactorsTable.secretEnc, row.secretEnc),
        ),
      )
      .returning({ userId: stepUpFactorsTable.userId });
    return done.length > 0;
  });
}

export interface WebauthnStepUpOptions {
  challenge: string; // base64url
  rpId: string;
  allowCredentials: string[]; // credential ids, base64url
}

/** Begin a WebAuthn step-up: issue a fresh single-use challenge for an already-
 *  registered credential. Returns null if the user has no verified credential.
 *  The client passes these options to navigator.credentials.get(). */
export async function beginWebauthnStepUp(
  tenantId: string,
  userId: string,
): Promise<WebauthnStepUpOptions | null> {
  const policy = webauthnPolicy();
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
    if (!row || !row.verifiedAt) return null;
    let env: WebauthnEnvelope;
    try {
      env = readEnvelope(tenantId, row.secretEnc);
    } catch {
      return null;
    }
    if (!env.credential) return null;
    const { randomChallenge } = await import("./webauthn");
    const challenge = randomChallenge();
    const nextEnc = writeEnvelope(tenantId, {
      credential: env.credential,
      pending: { challenge, exp: Date.now() + WEBAUTHN_CHALLENGE_TTL_MS },
    });
    await tx
      .update(stepUpFactorsTable)
      .set({ secretEnc: nextEnc, updatedAt: new Date() })
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
        ),
      );
    return {
      challenge,
      rpId: policy.rpId,
      allowCredentials: [env.credential.credentialId],
    };
  });
}

// --- OIDC (IdP-federated) enrollment + step-up -----------------------------
//
// Unlike TOTP/WebAuthn (a locally-verifiable proof), OIDC step-up is a browser
// redirect round-trip: the user authenticates at their own identity provider
// and the IdP returns an authorization code. We follow the authorization-code +
// PKCE flow (`lib/oidc.ts`, no SDK). Enrollment LINKS the user's federated
// identity: the verified `sub` claim is stored so every subsequent step-up must
// re-authenticate as that same subject. The per-attempt state/nonce/PKCE
// verifier live in the same encrypted `secret_enc` envelope (purpose
// OIDC_ENC_PURPOSE), single-use via a compare-and-swap, exactly like the
// WebAuthn pending challenge.

interface OidcEnvelope {
  /** Set once enrollment links a federated identity. */
  identity?: { sub: string };
  /** The in-flight authorization request (single-use). */
  pending?: { state: string; nonce: string; codeVerifier: string; exp: number };
}

/** Resolve + validate the OIDC relying-party policy from the environment. Only
 *  ever called on the oidc code path, so the dev/eval-gate default never reads it. */
function oidcPolicy(): OidcPolicy {
  const issuer = process.env.STEP_UP_OIDC_ISSUER;
  const clientId = process.env.STEP_UP_OIDC_CLIENT_ID;
  const clientSecret = process.env.STEP_UP_OIDC_CLIENT_SECRET;
  const redirectUri = process.env.STEP_UP_OIDC_REDIRECT_URI;
  if (!issuer || !clientId || !clientSecret || !redirectUri) {
    throw new Error(
      "STEP_UP_OIDC_ISSUER, STEP_UP_OIDC_CLIENT_ID, STEP_UP_OIDC_CLIENT_SECRET and STEP_UP_OIDC_REDIRECT_URI must be set when STEP_UP_PROVIDER=oidc",
    );
  }
  const scopesEnv = process.env.STEP_UP_OIDC_SCOPES;
  const scopes = scopesEnv
    ? scopesEnv.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
    : ["openid", "profile", "email"];
  if (!scopes.includes("openid")) scopes.unshift("openid");
  const subjectClaim = process.env.STEP_UP_OIDC_SUBJECT_CLAIM || "sub";
  return { issuer, clientId, clientSecret, redirectUri, scopes, subjectClaim };
}

function readOidcEnvelope(tenantId: string, raw: string): OidcEnvelope {
  return JSON.parse(
    decryptSecret(tenantId, raw, OIDC_ENC_PURPOSE),
  ) as OidcEnvelope;
}

function writeOidcEnvelope(tenantId: string, env: OidcEnvelope): string {
  return encryptSecret(tenantId, JSON.stringify(env), OIDC_ENC_PURPOSE);
}

export interface OidcAuthorizationOptions {
  authorizationUrl: string;
}

/** Issue a fresh authorization request (state/nonce/PKCE), persist it as the
 *  pending attempt, and return the IdP authorize URL. Shared by enrollment and
 *  step-up; `preserveIdentity` keeps the linked identity (step-up) vs resetting
 *  it (re-enrollment). */
async function beginOidcAuthorization(
  tenantId: string,
  userId: string,
  preserveIdentity: boolean,
): Promise<OidcAuthorizationOptions> {
  const policy = oidcPolicy();
  const { discover, buildAuthorizationUrl, pkcePair, randomUrlToken } =
    await import("./oidc");
  const discovery = await discover(policy.issuer);
  const state = randomUrlToken();
  const nonce = randomUrlToken();
  const { verifier, challenge } = pkcePair();
  const authorizationUrl = buildAuthorizationUrl({
    discovery,
    policy,
    state,
    nonce,
    codeChallenge: challenge,
  });
  await withTenant(tenantId, async (tx) => {
    const [row] = await tx
      .select()
      .from(stepUpFactorsTable)
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
        ),
      );
    let identity: OidcEnvelope["identity"];
    if (preserveIdentity && row) {
      try {
        identity = readOidcEnvelope(tenantId, row.secretEnc).identity;
      } catch {
        identity = undefined;
      }
    }
    const secretEnc = writeOidcEnvelope(tenantId, {
      identity,
      pending: { state, nonce, codeVerifier: verifier, exp: Date.now() + OIDC_CHALLENGE_TTL_MS },
    });
    await tx
      .insert(stepUpFactorsTable)
      .values({
        tenantId,
        userId,
        type: "oidc",
        secretEnc,
        // Re-enrollment resets verification; step-up keeps the prior state.
        verifiedAt: preserveIdentity ? (row?.verifiedAt ?? null) : null,
        lastUsedStep: null,
      })
      .onConflictDoUpdate({
        target: [stepUpFactorsTable.tenantId, stepUpFactorsTable.userId],
        set: {
          type: "oidc",
          secretEnc,
          verifiedAt: preserveIdentity ? (row?.verifiedAt ?? null) : null,
          lastUsedStep: null,
          updatedAt: new Date(),
        },
      });
  });
  return { authorizationUrl };
}

/** Begin (or restart) OIDC enrollment: issue an authorize URL and reset the
 *  factor to UNVERIFIED. The browser completes the IdP login and posts the
 *  returned code+state to finishOidcRegistration. */
export async function beginOidcRegistration(
  tenantId: string,
  userId: string,
): Promise<OidcAuthorizationOptions> {
  return beginOidcAuthorization(tenantId, userId, false);
}

/** The step-up token the client posts after the redirect: the IdP's
 *  authorization code + the state we issued. */
interface OidcCallbackToken {
  code: string;
  state: string;
}

function parseOidcToken(token: string): OidcCallbackToken | null {
  let parsed: { code?: unknown; state?: unknown };
  try {
    parsed = JSON.parse(token);
  } catch {
    return null;
  }
  if (typeof parsed.code !== "string" || typeof parsed.state !== "string") {
    return null;
  }
  return { code: parsed.code, state: parsed.state };
}

/** Run the authorization-code exchange + ID-token verification against a pending
 *  attempt. Returns the federated subject on success, or null on any failure
 *  (bad state, expired, exchange/verify error). Does NOT consume the pending
 *  attempt — the caller does that via CAS so concurrent/replayed callbacks lose. */
async function resolveOidcSubject(
  tenantId: string,
  pending: NonNullable<OidcEnvelope["pending"]>,
  cb: OidcCallbackToken,
): Promise<string | null> {
  // Constant-time state comparison + freshness.
  const expected = Buffer.from(pending.state, "utf8");
  const got = Buffer.from(cb.state, "utf8");
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
    return null;
  }
  if (pending.exp < Date.now()) return null;
  const policy = oidcPolicy();
  try {
    const { discover, exchangeCode, verifyIdToken } = await import("./oidc");
    const discovery = await discover(policy.issuer);
    const { idToken } = await exchangeCode({
      discovery,
      policy,
      code: cb.code,
      codeVerifier: pending.codeVerifier,
    });
    const claims = await verifyIdToken({
      idToken,
      discovery,
      policy,
      nonce: pending.nonce,
    });
    const subject = claims[policy.subjectClaim];
    if (typeof subject !== "string" || subject.length === 0) return null;
    return subject;
  } catch {
    return null;
  }
}

/** Finish enrollment: complete the code exchange, verify the ID token, and
 *  persist the federated subject as the VERIFIED linked identity (CAS on the
 *  pending attempt). Returns false on any failure. */
export async function finishOidcRegistration(
  tenantId: string,
  userId: string,
  token: OidcCallbackToken,
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
    let env: OidcEnvelope;
    try {
      env = readOidcEnvelope(tenantId, row.secretEnc);
    } catch {
      return false;
    }
    if (!env.pending) return false;
    const subject = await resolveOidcSubject(tenantId, env.pending, token);
    if (!subject) return false;
    const nextEnc = writeOidcEnvelope(tenantId, { identity: { sub: subject } });
    const done = await tx
      .update(stepUpFactorsTable)
      .set({
        secretEnc: nextEnc,
        verifiedAt: new Date(),
        lastUsedStep: null,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(stepUpFactorsTable.tenantId, tenantId),
          eq(stepUpFactorsTable.userId, userId),
          eq(stepUpFactorsTable.secretEnc, row.secretEnc),
        ),
      )
      .returning({ userId: stepUpFactorsTable.userId });
    return done.length > 0;
  });
}

/** Begin an OIDC step-up: issue a fresh authorize URL for an already-linked
 *  identity. Returns null if the user has no verified federated identity. */
export async function beginOidcStepUp(
  tenantId: string,
  userId: string,
): Promise<OidcAuthorizationOptions | null> {
  const status = await getFactorStatus(tenantId, userId);
  if (!status.verified) return null;
  return beginOidcAuthorization(tenantId, userId, true);
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

/** WebAuthn verifier. The step-up `token` is a JSON-encoded assertion
 *  ({credentialId, clientDataJSON, authenticatorData, signature}, all base64url).
 *  Looks up the VERIFIED credential + pending challenge, verifies the assertion,
 *  enforces the signature-counter clone guard, and clears the single-use
 *  challenge via a CAS on the prior envelope (so a replay / concurrent verify
 *  finds nothing to consume). */
const webauthnVerifier: StepUpVerifier = {
  kind: "webauthn",
  verify: async ({ tenantId, sub, token }) => {
    let policy: WebauthnPolicy;
    try {
      policy = webauthnPolicy();
    } catch {
      return false;
    }
    let assertion: {
      credentialId?: string;
      clientDataJSON?: string;
      authenticatorData?: string;
      signature?: string;
    };
    try {
      assertion = JSON.parse(token);
    } catch {
      return false;
    }
    if (
      !assertion.credentialId ||
      !assertion.clientDataJSON ||
      !assertion.authenticatorData ||
      !assertion.signature
    ) {
      return false;
    }
    return withTenant(tenantId, async (tx) => {
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
      let env: WebauthnEnvelope;
      try {
        env = readEnvelope(tenantId, row.secretEnc);
      } catch {
        return false;
      }
      if (!env.credential || !env.pending || env.pending.exp < Date.now()) {
        return false;
      }
      // The assertion must target the registered credential.
      if (assertion.credentialId !== env.credential.credentialId) return false;
      const { verifyAssertion } = await import("./webauthn");
      const result = verifyAssertion(
        {
          clientDataJSON: assertion.clientDataJSON!,
          authenticatorData: assertion.authenticatorData!,
          signature: assertion.signature!,
          expectedChallenge: env.pending.challenge,
        },
        { ...env.credential, signCount: row.lastUsedStep ?? 0 },
        policy,
      );
      if (!result) return false;
      // Consume the single-use challenge (drop `pending`) and advance the
      // counter, gated by a CAS on the exact prior envelope so a replayed or
      // concurrent assertion cannot also succeed.
      const consumed = writeEnvelope(tenantId, { credential: env.credential });
      const advanced = await tx
        .update(stepUpFactorsTable)
        .set({
          secretEnc: consumed,
          lastUsedStep: result.signCount,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(stepUpFactorsTable.tenantId, tenantId),
            eq(stepUpFactorsTable.userId, sub),
            eq(stepUpFactorsTable.secretEnc, row.secretEnc),
          ),
        )
        .returning({ userId: stepUpFactorsTable.userId });
      return advanced.length > 0;
    });
  },
};

/** OIDC verifier. The step-up `token` is a JSON-encoded callback
 *  ({code, state}). Looks up the user's VERIFIED linked identity + pending
 *  authorization attempt, exchanges the code, verifies the ID token, asserts the
 *  federated subject matches the enrolled identity, and consumes the single-use
 *  pending attempt via a CAS on the prior envelope. */
const oidcVerifier: StepUpVerifier = {
  kind: "oidc",
  verify: async ({ tenantId, sub, token }) => {
    const cb = parseOidcToken(token);
    if (!cb) return false;
    return withTenant(tenantId, async (tx) => {
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
      let env: OidcEnvelope;
      try {
        env = readOidcEnvelope(tenantId, row.secretEnc);
      } catch {
        return false;
      }
      if (!env.identity || !env.pending) return false;
      const subject = await resolveOidcSubject(tenantId, env.pending, cb);
      if (!subject) return false;
      // The federated identity must match the one linked at enrollment.
      const a = Buffer.from(subject, "utf8");
      const b = Buffer.from(env.identity.sub, "utf8");
      if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
      // Consume the single-use pending attempt (drop it), gated by a CAS on the
      // exact prior envelope so a replayed/concurrent callback cannot also win.
      const consumed = writeOidcEnvelope(tenantId, { identity: env.identity });
      const advanced = await tx
        .update(stepUpFactorsTable)
        .set({ secretEnc: consumed, updatedAt: new Date() })
        .where(
          and(
            eq(stepUpFactorsTable.tenantId, tenantId),
            eq(stepUpFactorsTable.userId, sub),
            eq(stepUpFactorsTable.secretEnc, row.secretEnc),
          ),
        )
        .returning({ userId: stepUpFactorsTable.userId });
      return advanced.length > 0;
    });
  },
};

/** Resolve the active verifier from STEP_UP_PROVIDER. */
export function getStepUpVerifier(): StepUpVerifier {
  const provider = stepUpProvider();
  if (provider === "totp") return totpVerifier;
  if (provider === "webauthn") return webauthnVerifier;
  if (provider === "oidc") return oidcVerifier;
  return devVerifier;
}

// Exposed for unit tests of the at-rest crypto round-trip.
export const __testing = { encryptSecret, decryptSecret };
