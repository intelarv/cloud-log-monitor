// Labeled secrets-in-logs fixtures. Secrets are a higher-severity finding
// class than PHI (threat_model Assets: "Secrets-in-logs ... compromise grants
// direct system access"). The eval measures recall: of the labeled secret
// substrings, how many does scanForPhi catch.
//
// All values are SYNTHETIC and well-known non-secret examples (AWS docs'
// AKIAIOSFODNN7EXAMPLE, a structurally-valid but meaningless JWT, etc.).
// The classes that began as M0 gaps (GitHub PAT, Google API key, Slack token,
// PEM private key, DB URL password, generic password=) are now all covered by
// dedicated detectors in `lib/redact.ts` — they were added to close the gap the
// eval surfaced, and the suite now records full (recall=1.0) coverage. They
// remain here as regression fixtures so any future detector change that drops a
// class is caught.

export interface SecretFixture {
  id: string;
  kind: string;
  text: string;
  secret: string;
}

export const SECRET_FIXTURES: SecretFixture[] = [
  {
    id: "aws-akid-1",
    kind: "aws_access_key_id",
    text: "config loaded creds=AKIAIOSFODNN7EXAMPLE for uploader",
    secret: "AKIAIOSFODNN7EXAMPLE",
  },
  {
    id: "aws-asia-1",
    kind: "aws_temp_access_key_id",
    text: "assumed role token=ASIAABCDEFGHIJKLMNOP issued",
    secret: "ASIAABCDEFGHIJKLMNOP",
  },
  {
    id: "jwt-1",
    kind: "jwt",
    text:
      "auth header bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
      ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ" +
      ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c received",
    secret:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
      ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ" +
      ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  },
  {
    id: "github-pat-1",
    kind: "github_pat",
    text: "git remote auth token ghp_16C7e42F292c6912E7710c838347Ae178B4aXX set",
    secret: "ghp_16C7e42F292c6912E7710c838347Ae178B4aXX",
  },
  {
    id: "google-api-1",
    kind: "google_api_key",
    text: "maps client key AIzaSyA1234567890abcdefghijklmnopqrstuvw rotated",
    secret: "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
  },
  {
    id: "slack-token-1",
    kind: "slack_token",
    text: "channel webhook token xoxb-1234567890-0987654321-abcdEFGHijklMNOP loaded",
    secret: "xoxb-1234567890-0987654321-abcdEFGHijklMNOP",
  },
  {
    id: "pem-1",
    kind: "private_key_pem",
    text: "loaded key -----BEGIN PRIVATE KEY-----MIIBVgIBADANBg-----END PRIVATE KEY----- ok",
    secret: "-----BEGIN PRIVATE KEY-----",
  },
  {
    id: "dburl-1",
    kind: "db_url_password",
    text: "DATABASE_URL=postgres://svc:S3cretPass@db.internal:5432/app connected",
    secret: "S3cretPass",
  },
  {
    id: "password-kv-1",
    kind: "generic_password",
    text: "admin login attempt with password=Sup3rSecretValue! denied",
    secret: "Sup3rSecretValue!",
  },

  // --- M13.4: additional secret classes. ---
  {
    // AWS secret access key (the 40-char secret). Context-anchored: only the
    // access-key ID was covered before. Uses the AWS docs' example secret.
    id: "aws-secret-1",
    kind: "aws_secret_access_key",
    text: "env aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY exported",
    secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  },
  {
    id: "stripe-1",
    kind: "stripe_key",
    text: "billing stripe secret sk_live_4eC39HqLyjWDarjtT1zdp7dc loaded",
    secret: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
  },
  {
    id: "twilio-1",
    kind: "twilio_sid",
    text: "sms provider account ACa1b2c3d4e5f6071829304a5b6c7d8e9f configured",
    secret: "ACa1b2c3d4e5f6071829304a5b6c7d8e9f",
  },
  {
    id: "sendgrid-1",
    kind: "sendgrid_key",
    text: "mailer key SG.ngeVfQFYQ1234567890ab.TwL2iGAB1234567890cdefghijklmnopqr set",
    secret: "SG.ngeVfQFYQ1234567890ab.TwL2iGAB1234567890cdefghijklmnopqr",
  },
  {
    id: "openai-1",
    kind: "openai_api_key",
    text: "llm client sk-proj-abcdefABCDEF1234567890ghijklmnopqr initialized",
    secret: "sk-proj-abcdefABCDEF1234567890ghijklmnopqr",
  },
  {
    id: "anthropic-1",
    kind: "anthropic_api_key",
    text: "agent runtime sk-ant-api03-abcdefGHIJKL1234567890mnopqrstuv used",
    secret: "sk-ant-api03-abcdefGHIJKL1234567890mnopqrstuv",
  },
  {
    id: "npm-1",
    kind: "npm_token",
    text: "ci registry npm_abcdefghijklmnopqrstuvwxyz0123456789 published",
    secret: "npm_abcdefghijklmnopqrstuvwxyz0123456789",
  },
  {
    id: "vault-1",
    kind: "vault_token",
    text: "secrets fetch hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789 renewed",
    secret: "hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789",
  },
  {
    // Azure storage account key — context-anchored `AccountKey=<86 base64>==`.
    id: "azure-storage-1",
    kind: "azure_storage_key",
    text:
      "conn DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" +
      "01234567890123456789012345678901234567890123456789012345678901234567890123456789ABCDEF==" +
      ";EndpointSuffix=core.windows.net",
    secret:
      "01234567890123456789012345678901234567890123456789012345678901234567890123456789ABCDEF==",
  },
  {
    // GCP service-account JSON private key — the PEM body is covered by the
    // existing private_key_pem detector; this locks that coverage.
    id: "gcp-sa-1",
    kind: "gcp_service_account_key",
    text: '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----MIIEvAIBA-----END PRIVATE KEY-----\\n"}',
    secret: "-----BEGIN PRIVATE KEY-----",
  },

  // --- M13.5: generic high-entropy secret (no recognizable provider prefix). ---
  {
    id: "entropy-hex-1",
    kind: "high_entropy_hex",
    text: "service config api_key=9f8e7d6c5b4a3210ffeeddccbbaa9988 loaded",
    secret: "9f8e7d6c5b4a3210ffeeddccbbaa9988",
  },
  {
    id: "entropy-b64-1",
    kind: "high_entropy_base64",
    text: 'integration client_secret="aGVsbG8td29ybGQtc2VjcmV0LTEyMzQ1Njc4OTA" rotated',
    secret: "aGVsbG8td29ybGQtc2VjcmV0LTEyMzQ1Njc4OTA",
  },
];
