// Labeled secrets-in-logs fixtures. Secrets are a higher-severity finding
// class than PHI (threat_model Assets: "Secrets-in-logs ... compromise grants
// direct system access"). The eval measures recall: of the labeled secret
// substrings, how many does scanForPhi catch.
//
// All values are SYNTHETIC and well-known non-secret examples (AWS docs'
// AKIAIOSFODNN7EXAMPLE, a structurally-valid but meaningless JWT, etc.).
// Several classes (GitHub PAT, Google API key, Slack token, PEM private key,
// DB URL password, generic password=) are NOT covered by the M0 detectors and
// are included so the eval records the gap.

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
];
