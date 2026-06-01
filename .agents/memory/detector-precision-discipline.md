---
name: Detector precision discipline (scanForPhi)
description: Rule for adding PHI/PII/secret detectors to lib/redact.ts without regressing benign-log precision.
---

# Detector precision discipline

Any new detector added to `scanForPhi` (`artifacts/api-server/src/lib/redact.ts`)
must hold **zero false positives** on the benign operational-log corpus that the
credential-free eval gate exercises (detector-phi / detector-secrets suites).

**Why:** the eval gate fails on benign FPs, but more importantly real ops logs are
saturated with ID-shaped noise (host:port, file:line:col, git SHAs, UUIDs, request
ids, employee/order numbers). A pattern that matches "the right shape" almost always
also matches benign noise.

**How to apply — a detector ships only if it is one of:**
- **Shape-distinctive** enough on its own (structured prefixes like `sk-proj-`,
  `SG.`, `hvs.`, `AccountKey=`; an HMAC/checksum; a long all-alnum blob of a fixed
  known length).
- **Context-anchored** to a keyword via lookbehind when the bare shape is ambiguous.
  Bare ID shapes (DEA `[A-Za-z][A-Za-z9]\d{7}`, license plate, passport, a non-prefixed
  `sk-…` slug) collide with ordinary enterprise IDs and MUST be anchored — a checksum
  alone is not enough (DEA's check digit passes ~1 in 10 random IDs).

**Two specifics that bit during M13:**
- IPv6: use negative hex/colon lookarounds `(?<![0-9A-Fa-f:])…(?![0-9A-Fa-f:])`, NOT
  `\b`. With `\b` an ordered alternation stops early on `fe80::` and the colon-boundary
  also lets `host:port` / `file.js:line:col` noise match.
- `high_entropy_secret` intentionally overlaps the specific secret detectors
  (defense-in-depth). It fires only on secret-shaped keys (`api_key`/`secret`/`token`/…)
  past a Shannon-entropy floor — the key-context gate is what keeps benign base64/hex out.

After adding/changing a detector: run the redact unit tests, then `pnpm run eval:gate`
(placeholder DB env is fine — deterministic suites import `lib/db` but never connect),
and re-baseline with `eval:update` only once precision is proven clean.
