// Labeled secrets-in-logs fixtures. Secrets are a higher-severity finding
// class than PHI (threat_model Assets: "Secrets-in-logs ... compromise grants
// direct system access"). The detector-secrets eval measures precision AND
// recall against these labeled spans.
//
// The corpus has two cohorts:
//   - SECRET_FIXTURES: positive cases. Each carries a `shape` so the eval can
//     report per-shape recall. Beyond the original short CLEAN lines, the corpus
//     now includes realistic, messy PRODUCTION shapes — secrets embedded in JSON
//     log envelopes, logfmt/key=value lines, stack traces, and connection
//     strings — because that is how credentials actually leak into ops logs, and
//     those shapes surface accuracy gaps the clean one-liners hide.
//   - BENIGN_SECRET_FIXTURES: negative cases. Near-miss tokens that share the
//     SHAPE of a credential (git SHAs, request/trace UUIDs, hex etags, SSH
//     fingerprints, kebab-case service slugs) but are NOT secrets. They must
//     yield ZERO secrets-classified hits; any hit here is a false positive and
//     drags precision down — this is what stops a "flag every hex blob" detector
//     from scoring well on recall alone.
//
// All values are SYNTHETIC and well-known non-secret examples (AWS docs'
// AKIAIOSFODNN7EXAMPLE, a structurally-valid but meaningless JWT, etc.).
// The classes that began as M0 gaps (GitHub PAT, Google API key, Slack token,
// PEM private key, DB URL password, generic password=) are now all covered by
// dedicated detectors in `lib/redact.ts`. They remain here as regression
// fixtures so any future detector change that drops a class is caught.

export interface SecretFixture {
  id: string;
  kind: string;
  text: string;
  /** The single labeled credential in `text`. INVARIANT: exactly one labeled
   *  secret per fixture — the eval's precision accounting treats any
   *  secrets-classified hit that does NOT overlap this span as a false
   *  positive, so a second real secret on the same line would be miscounted.
   *  Add a multi-secret line only after evolving this to a `secrets[]` shape. */
  secret: string;
  /** Production log shape this fixture exercises. Default "clean". */
  shape?: "clean" | "json" | "kv" | "stacktrace" | "connstring";
  /** Accepted, documented miss. Excluded from the gated f1 and surfaced as
   *  `known_gap_missed` so a documented limitation doesn't read as a silent
   *  regression; a NEW undocumented miss still fails the suite loudly. */
  knownGap?: string;
}

/** A near-miss that LOOKS credential-shaped but is not a secret. Must produce
 *  zero secrets-classified hits. `note` records why it is benign. */
export interface BenignSecretFixture {
  id: string;
  text: string;
  note: string;
}

export const SECRET_FIXTURES: SecretFixture[] = [
  {
    id: "aws-akid-1",
    kind: "aws_access_key_id",
    text: "config loaded creds=AKIAIOSFODNN7EXAMPLE for uploader",
    secret: "AKIAIOSFODNN7EXAMPLE",
    shape: "kv",
  },
  {
    id: "aws-asia-1",
    kind: "aws_temp_access_key_id",
    text: "assumed role token=ASIAABCDEFGHIJKLMNOP issued",
    secret: "ASIAABCDEFGHIJKLMNOP",
    shape: "kv",
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
    shape: "clean",
  },
  {
    id: "github-pat-1",
    kind: "github_pat",
    text: "git remote auth token ghp_16C7e42F292c6912E7710c838347Ae178B4aXX set",
    secret: "ghp_16C7e42F292c6912E7710c838347Ae178B4aXX",
    shape: "clean",
  },
  {
    id: "google-api-1",
    kind: "google_api_key",
    text: "maps client key AIzaSyA1234567890abcdefghijklmnopqrstuvw rotated",
    secret: "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
    shape: "clean",
  },
  {
    id: "slack-token-1",
    kind: "slack_token",
    text: "channel webhook token xoxb-1234567890-0987654321-abcdEFGHijklMNOP loaded",
    secret: "xoxb-1234567890-0987654321-abcdEFGHijklMNOP",
    shape: "clean",
  },
  {
    id: "pem-1",
    kind: "private_key_pem",
    text: "loaded key -----BEGIN PRIVATE KEY-----MIIBVgIBADANBg-----END PRIVATE KEY----- ok",
    secret: "-----BEGIN PRIVATE KEY-----",
    shape: "clean",
  },
  {
    id: "dburl-1",
    kind: "db_url_password",
    text: "DATABASE_URL=postgres://svc:S3cretPass@db.internal:5432/app connected",
    secret: "S3cretPass",
    shape: "connstring",
  },
  {
    id: "password-kv-1",
    kind: "generic_password",
    text: "admin login attempt with password=Sup3rSecretValue! denied",
    secret: "Sup3rSecretValue!",
    shape: "kv",
  },

  // --- M13.4: additional secret classes. ---
  {
    // AWS secret access key (the 40-char secret). Context-anchored: only the
    // access-key ID was covered before. Uses the AWS docs' example secret.
    id: "aws-secret-1",
    kind: "aws_secret_access_key",
    text: "env aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY exported",
    secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    shape: "kv",
  },
  {
    id: "stripe-1",
    kind: "stripe_key",
    text: "billing stripe secret sk_live_4eC39HqLyjWDarjtT1zdp7dc loaded",
    secret: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    shape: "clean",
  },
  {
    id: "twilio-1",
    kind: "twilio_sid",
    text: "sms provider account ACa1b2c3d4e5f6071829304a5b6c7d8e9f configured",
    secret: "ACa1b2c3d4e5f6071829304a5b6c7d8e9f",
    shape: "clean",
  },
  {
    id: "sendgrid-1",
    kind: "sendgrid_key",
    text: "mailer key SG.ngeVfQFYQ1234567890ab.TwL2iGAB1234567890cdefghijklmnopqr set",
    secret: "SG.ngeVfQFYQ1234567890ab.TwL2iGAB1234567890cdefghijklmnopqr",
    shape: "clean",
  },
  {
    id: "openai-1",
    kind: "openai_api_key",
    text: "llm client sk-proj-abcdefABCDEF1234567890ghijklmnopqr initialized",
    secret: "sk-proj-abcdefABCDEF1234567890ghijklmnopqr",
    shape: "clean",
  },
  {
    id: "anthropic-1",
    kind: "anthropic_api_key",
    text: "agent runtime sk-ant-api03-abcdefGHIJKL1234567890mnopqrstuv used",
    secret: "sk-ant-api03-abcdefGHIJKL1234567890mnopqrstuv",
    shape: "clean",
  },
  {
    id: "npm-1",
    kind: "npm_token",
    text: "ci registry npm_abcdefghijklmnopqrstuvwxyz0123456789 published",
    secret: "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    shape: "clean",
  },
  {
    id: "vault-1",
    kind: "vault_token",
    text: "secrets fetch hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789 renewed",
    secret: "hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789",
    shape: "clean",
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
    shape: "connstring",
  },
  {
    // GCP service-account JSON private key — the PEM body is covered by the
    // existing private_key_pem detector; this locks that coverage.
    id: "gcp-sa-1",
    kind: "gcp_service_account_key",
    text: '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----MIIEvAIBA-----END PRIVATE KEY-----\\n"}',
    secret: "-----BEGIN PRIVATE KEY-----",
    shape: "json",
  },

  // --- M13.5: generic high-entropy secret (no recognizable provider prefix). ---
  {
    id: "entropy-hex-1",
    kind: "high_entropy_hex",
    text: "service config api_key=9f8e7d6c5b4a3210ffeeddccbbaa9988 loaded",
    secret: "9f8e7d6c5b4a3210ffeeddccbbaa9988",
    shape: "kv",
  },
  {
    id: "entropy-b64-1",
    kind: "high_entropy_base64",
    text: 'integration client_secret="aGVsbG8td29ybGQtc2VjcmV0LTEyMzQ1Njc4OTA" rotated',
    secret: "aGVsbG8td29ybGQtc2VjcmV0LTEyMzQ1Njc4OTA",
    shape: "kv",
  },

  // ---------------------------------------------------------------------------
  // Production-shaped positives. Same credentials, embedded in the messy log
  // shapes credentials actually leak in (JSON envelopes, stack traces,
  // connection strings) — to prove recall survives realistic formatting.
  // ---------------------------------------------------------------------------
  {
    // AWS access-key id inside a structured JSON log line.
    id: "json-aws-akid-1",
    kind: "aws_access_key_id",
    text: '{"ts":"2025-02-01T12:00:00Z","level":"warn","caller":"uploader","creds":"AKIAIOSFODNN7EXAMPLE","region":"us-east-1"}',
    secret: "AKIAIOSFODNN7EXAMPLE",
    shape: "json",
  },
  {
    // GitHub PAT inside a JSON log line.
    id: "json-github-pat-1",
    kind: "github_pat",
    text: '{"ts":"2025-02-01T12:00:01Z","level":"error","msg":"clone failed","git_token":"ghp_16C7e42F292c6912E7710c838347Ae178B4aXX"}',
    secret: "ghp_16C7e42F292c6912E7710c838347Ae178B4aXX",
    shape: "json",
  },
  {
    // JWT carried in a Bearer header inside a JSON access log.
    id: "json-jwt-1",
    kind: "jwt",
    text:
      '{"msg":"token refresh","authorization":"Bearer ' +
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
      ".eyJzdWIiOiJhYmMxMjMifQ" +
      '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c","svc":"auth"}',
    secret:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
      ".eyJzdWIiOiJhYmMxMjMifQ" +
      ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    shape: "json",
  },
  {
    // Stripe secret key spilled into an error stack trace.
    id: "stacktrace-stripe-1",
    kind: "stripe_key",
    text:
      "PaymentError: charge failed with sk_live_4eC39HqLyjWDarjtT1zdp7dc\n" +
      "    at charge (billing.js:42:13)\n" +
      "    at process (worker.js:8:5)",
    secret: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    shape: "stacktrace",
  },
  {
    // generic password= leaked in a stack trace frame.
    id: "stacktrace-password-1",
    kind: "generic_password",
    text:
      "AuthError: invalid credentials password=Tr0ub4dor&3xtra\n" +
      "    at login (auth.js:88:7)\n" +
      "    at handler (router.js:21:9)",
    secret: "Tr0ub4dor&3xtra",
    shape: "stacktrace",
  },
  {
    // DB password in an AMQP broker connection string.
    id: "connstring-amqp-1",
    kind: "db_url_password",
    text: "worker connecting amqp://svc:R0utePassWord@mq.internal:5672/vhost retry=0",
    secret: "R0utePassWord",
    shape: "connstring",
  },
  {
    // Redis password in a connection string inside a JSON config dump.
    id: "json-redis-url-1",
    kind: "db_url_password",
    text: '{"redis_url":"redis://default:C4cheSecretPw@cache.internal:6379/0","pool":8}',
    secret: "C4cheSecretPw",
    shape: "json",
  },
  {
    // Opaque high-entropy client secret in a logfmt line (no provider prefix).
    id: "kv-high-entropy-1",
    kind: "high_entropy_base64",
    text: "integration sync client_secret=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA token refreshed",
    secret: "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
    shape: "kv",
  },

  // ---------------------------------------------------------------------------
  // HTTP Basic-auth credentials — `Authorization: Basic <base64(user:pass)>`
  // (RFC 7617). Now covered by the dedicated `http_basic_auth` detector in
  // `lib/redact.ts`: anchored on the `Basic ` scheme marker, then gated to a
  // token that decodes to a printable `user:pass` shape. This closes the former
  // knownGap without the production NER path and without regressing precision —
  // the benign controls below prove a `Basic ` token that is NOT credentials,
  // and a colon-bearing base64 blob with no scheme marker, both stay unflagged.
  // ---------------------------------------------------------------------------
  {
    id: "basic-auth-1",
    kind: "http_basic_auth",
    text: 'GET /api 401 authorization="Basic dXNlcjpzdXAzcnMzY3JldA==" client=svc',
    secret: "dXNlcjpzdXAzcnMzY3JldA==",
    shape: "kv",
  },
];

export const BENIGN_SECRET_FIXTURES: BenignSecretFixture[] = [
  {
    id: "benign-git-sha-1",
    text: "deploy pipeline build=ci commit=3f6a1c9d2e8b4a7f0c1d2e3f4a5b6c7d8e9f0a1b status=ok",
    note: "40-char git commit SHA under a non-secret key; no provider prefix, not AC/SK-prefixed.",
  },
  {
    id: "benign-basic-not-creds-1",
    text: 'request denied authorization="Basic aGVsbG8gd29ybGQ=" path=/x',
    note: 'A `Basic ` token that base64-decodes to "hello world" — no colon, not a user:pass credential, so the http_basic_auth detector must reject it.',
  },
  {
    id: "benign-basic-no-scheme-1",
    text: "event payload b64=dXNlcjpwYXNzd29yZA== source=svc",
    note: 'A base64 blob that decodes to "user:password" but carries no `Basic ` scheme marker, so it must NOT be flagged — proves the scheme anchor is required.',
  },
  {
    id: "benign-request-uuid-1",
    text: '{"level":"info","request_id":"550e8400-e29b-41d4-a716-446655440000","route":"/findings"}',
    note: "Request-id UUID; hyphenated, `request_id` is not a high-entropy-anchored key.",
  },
  {
    id: "benign-ssh-fingerprint-1",
    text: "sshd host key fingerprint SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 accepted",
    note: "SSH host-key fingerprint; bare `key` is not anchored and the b64 carries no provider prefix.",
  },
  {
    id: "benign-trace-hex-1",
    text: "span end trace_id=9f8e7d6c5b4a3210ffeeddccbbaa9988 service=member-svc sampled=true",
    note: "32-hex trace id — identical SHAPE to entropy-hex-1 but under a non-secret key, so it must not flag.",
  },
  {
    id: "benign-etag-md5-1",
    text: '{"path":"/static/app.js","etag":"d41d8cd98f00b204e9800998ecf8427e","status":200}',
    note: "MD5 etag (32 hex) under `etag`; not a secret key, not AC/SK-prefixed.",
  },
  {
    id: "benign-low-entropy-token-1",
    text: "feature gate token=enabled cohort=beta rollout=stable",
    note: "`token=enabled` — anchored key but the value is a short dictionary word, below the entropy/length floor.",
  },
  {
    id: "benign-kebab-sk-slug-1",
    text: "routing target sk-prod-us-east-1-webhook healthy latency=12ms",
    note: "kebab-case service slug starting `sk-`; not `sk_live/test_` and not a 40-char alnum key.",
  },
];
