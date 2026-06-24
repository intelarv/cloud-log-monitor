// Browser-side WebAuthn ceremony helpers for STEP_UP_PROVIDER=webauthn.
//
// The server speaks base64url for every binary field (challenge, user id,
// credential id, attestation, assertion) and the browser WebAuthn API speaks
// ArrayBuffer, so this module is the single seam that converts between them and
// drives navigator.credentials.{create,get}. Kept framework-free so it can be
// unit-tested directly.
import type {
  WebauthnRegistrationOptions,
  WebauthnStepUpOptions,
} from "@workspace/api-client-react";

export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function webauthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined"
  );
}

/** Drive navigator.credentials.create() from the server's registration options.
 *  Returns the base64url attestation fields the /register/finish endpoint wants.
 *  Requested algs (ES256, RS256) match the server verifier's supported set. */
export async function performWebauthnRegistration(
  opts: WebauthnRegistrationOptions,
): Promise<{ attestationObject: string; clientDataJSON: string }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: b64urlToBytes(opts.challenge),
      rp: { id: opts.rpId, name: opts.rpName },
      user: {
        id: b64urlToBytes(opts.userIdB64url),
        name: opts.userName,
        displayName: opts.userName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: { userVerification: "preferred" },
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No credential returned");
  const response = cred.response as AuthenticatorAttestationResponse;
  return {
    attestationObject: bytesToB64url(response.attestationObject),
    clientDataJSON: bytesToB64url(response.clientDataJSON),
  };
}

/** Drive navigator.credentials.get() from the server's assertion challenge and
 *  assemble the JSON step-up token (all fields base64url) the /auth/step-up
 *  endpoint parses for the webauthn provider. */
export async function performWebauthnAssertion(
  opts: WebauthnStepUpOptions,
): Promise<string> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToBytes(opts.challenge),
      rpId: opts.rpId,
      allowCredentials: opts.allowCredentials.map((id) => ({
        type: "public-key" as const,
        id: b64urlToBytes(id),
      })),
      userVerification: "preferred",
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No assertion returned");
  const response = cred.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    credentialId: bytesToB64url(cred.rawId),
    clientDataJSON: bytesToB64url(response.clientDataJSON),
    authenticatorData: bytesToB64url(response.authenticatorData),
    signature: bytesToB64url(response.signature),
  });
}
