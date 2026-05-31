# Eval suite (M11)

Fixture-based, score-emitting quality harness that **measures** the existing
detectors, redactor, agent-defense policy, and chat agent — it does not change
them. Separate from the unit test suite.

## Run

```bash
pnpm --filter @workspace/api-server run eval          # run + gate against baseline
pnpm --filter @workspace/api-server run eval:update   # run + rewrite baseline.json
EVAL_LLM=1 pnpm --filter @workspace/api-server run eval  # also run live LLM/DB suites
```

## CI gate (runs on every change)

The six deterministic suites + regression gate run automatically as a
credential-free quality gate, mirroring `helm:matrix` / `tf:fmt`:

```bash
pnpm run eval:gate        # bash deploy/scripts/eval-gate.sh — deterministic, secret-free
pnpm run eval:gate:llm    # bash deploy/scripts/eval-gate-llm.sh — adds EVAL_LLM=1 suites (needs creds)
```

- `eval:gate` is registered as the `eval-gate` validation command, so it runs as
  a CI-style check on changes. A regression >5pt vs `evals/baseline.json` fails it.
- The wrapper injects a placeholder `DATABASE_URL`/`SESSION_SECRET` (the
  deterministic suites import `lib/db` but never connect) and force-unsets
  `EVAL_LLM` so the gate stays credential-free regardless of ambient env.
- `eval:gate:llm` is the nightly/manual job for the credentialed suites; it
  requires a real `DATABASE_URL` + configured LLM runtime and is never part of
  the per-change gate.

## Nightly automation (the AI-backed suites)

The two credentialed suites (`citation-live`, `agent-agreement`) exercise the
live LLM + DB, so they can't run in the secret-free per-change gate. They run on
a schedule instead via `pnpm run eval:gate:llm`:

- **Kubernetes:** the Helm chart ships a `CronJob` (`evalGate.nightly` in
  `deploy/helm/phi-audit/values.yaml`, off by default). Enable it with an
  `eval`-target image and it runs `eval:gate:llm` nightly using the same
  `DATABASE_URL` / LLM / embedder config the API uses. See `deploy/README.md`
  → "Nightly eval gate".
- **Replit:** wire `pnpm run eval:gate:llm` as a Replit Scheduled Deployment
  with `DATABASE_URL` + an LLM runtime configured (see `deploy/README.md`).

### Hard-fail policy (what the nightly job pages on)

- Deterministic suite regressions > 5pt vs `baseline.json` **always** hard-fail.
- A live suite that crashes or emits no result **always** hard-fails (vitest
  exits non-zero before the gate).
- Live-suite **score** regressions are surfaced as warnings by default — these
  suites are non-deterministic, so delta-based paging would be flaky. Set
  `EVAL_LLM_MIN_SCORE` (an absolute floor, 0..1) to turn any live suite scoring
  below it into a hard failure — use it to page on catastrophic live-agent
  regressions without run-to-run noise. `gate.mjs` reads it from the env;
  `eval-gate-llm.sh` reports whether the floor is active.

### Channel alerting on a nightly run

After every nightly run, `eval-gate-llm.sh` invokes the notifier, which posts a
concise summary (per-suite scores + which check tripped) to any configured
channel before the script re-exits with the gate's exit code. It reuses the
**same** `CHANNEL_*` env config and severity gating as the application's finding
alerts:

- Slack incoming webhook: `CHANNEL_SLACK_WEBHOOK_URL` [+ `CHANNEL_SLACK_MIN_SEVERITY`].
  Slack posts use a Block Kit attachment with a severity-colored bar (red/amber/
  green) and a one-word headline (`FAILED` / `WARNINGS` / `PASSED`) so the daily
  heads-up is scannable at a glance; failures/warnings and the per-suite scores
  sit in code blocks below the headline. A plain-text `text` fallback is always
  included for clients/push notifications that don't render Block Kit.
- Generic HMAC-signed webhook: `CHANNEL_WEBHOOK_URL` + `CHANNEL_WEBHOOK_SECRET`
  (≥16) + `CHANNEL_WEBHOOK_ALLOWED_HOSTS` [+ `CHANNEL_WEBHOOK_MIN_SEVERITY`]. The
  body is signed with the same scheme as `src/lib/channels/adapters/webhook.ts`
  and carries structured fields (`outcome`, `suites`, `failures`, `warnings`).

#### Trend vs. the previous nightly run

A single night's pass/warn/fail can't reveal a *slow* slide: a suite that erodes
a fraction of a point per night stays inside the 5pt regression tolerance for
days before the gate finally trips. To surface that drift early, every nightly
run appends its per-suite scores to a small rolling history
(`evals/score-history.json`, gitignored — sibling of `results/` because
`pnpm run eval` wipes `results/`), and the notifier shows each suite's change
vs. the **previous** run:

- `▲ +0.5pt` — improved, `▼ -1.2pt` — dropped (the one on-call watches),
  `▬ ±0.0pt` — unchanged, `(new)` — no prior run to compare.
- The Slack Block Kit `suite scores` block and the plain-text fallback both
  carry the indicator; the generic webhook payload adds a structured `trends`
  map (`{ suite: { direction, deltaPt, prev } }`).
- `EVAL_HISTORY_LIMIT` (default `30`) caps how many recent runs are retained.

The trend is read from the **prior** runs before this run is appended, so a suite
is never compared against itself. Recording is best-effort and never changes the
job's exit code. In an ephemeral CI/cron pod, mount a durable path at
`evals/score-history.json` (or a small volume) so the history survives across
nightly invocations; without it each run starts cold and every suite shows
`(new)`.

**`EVAL_NOTIFY_ON` (`fail` | `warn` | `always`, default `fail`)** controls which
run outcomes post. The notifier classifies each run from
`evals/results/gate-summary.json` as one of:

| Outcome | When | Severity | Posts under |
|---|---|---|---|
| `failed` | gate hard-failed (regression / floor / execution failure) | `high` | `fail`, `warn`, `always` |
| `warned` | passed but produced non-fatal gate warnings (e.g. a live suite that ran without a baseline, or a below-tolerance drop) | `warning` | `warn`, `always` |
| `clean` | passed with no warnings (all-green confirmation) | `warning` | `always` |

Because success/warning runs map to **`warning`** severity, the existing
per-channel `CHANNEL_*_MIN_SEVERITY` gating still applies: a channel pinned to
`high` (or `critical`) never receives the warning-class heads-up or all-green
confirmation, only the `high`-severity hard-fail. Use `EVAL_NOTIFY_ON=always`
plus a `warning`-level channel to get a daily "all good" so silence isn't
ambiguous, or keep the default `fail` to page only on hard-fails.

**`EVAL_NOTIFY_RECOVERY` (default on; opt out with `off` | `false` | `0` | `no`)**
controls the **recovery note**. A hard-fail run pages PagerDuty (a `trigger`),
and the next passing run auto-resolves that incident — but on Slack/webhook the
page just vanishes silently. To explain it, when a passing run follows a prior
**failing** run, the notifier posts one concise `[RECOVERED]` line naming the
suites that came back green (read from the prior run's recorded failing-suite
list in `score-history.json`). It fires **only** when the normal run summary
would not otherwise post (i.e. under the default `EVAL_NOTIFY_ON=fail`), so a
recovery night never produces both a recovery note *and* a full confirmation;
under `warn`/`always` the normal all-green confirmation already covers it.
Routine consecutive green nights never trigger it — there is no prior fail to
recover from. The recovery note honors the same `warning`-class per-channel
`CHANNEL_*_MIN_SEVERITY` gating and is **never sent to PagerDuty** (which gets
the auto-resolve instead). When the trailing failing streak's start timestamp is
recoverable from history, the note also appends how long the gate had been
failing (e.g. `(was failing for ~3h)`) so on-call sees the blast radius at a
glance.

**Flapping mute.** A gate that bounces fail→pass repeatedly would otherwise spam
a `[RECOVERED]` note on every bounce. When at least
`EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD` (default `3`) recoveries already landed
within `EVAL_NOTIFY_RECOVERY_FLAP_WINDOW_MINUTES` (default `360` = 6h), the
notifier suppresses the recovery note (logging why) — on-call already knows the
gate is unstable. The defaults never trip on the 24h nightly cadence; set the
threshold to `0` to disable muting entirely. PagerDuty still auto-resolves on the
passing run regardless of the mute.

**Inert when no channel is configured** — matches adapter behavior. The payload
is scores + suite names only (synthetic fixtures, no PHI), so it is sent outside
the PHI-hard-gated `ChannelEnvelope`. `gate.mjs` writes the verdict to
`evals/results/gate-summary.json`; `evals/notify.mjs` (pure ESM, runnable by
`node`) reads it and sends. The notifier never throws and never changes the job's
exit code.

- Suites live in `src/evals/*.eval.ts` (typechecked, excluded from `pnpm test`).
- Fixtures in `src/evals/fixtures/` are **synthetic** (no real PHI in dev).
- Each suite writes `evals/results/<suite>.json` (gitignored, regenerated).
- `evals/gate.mjs` compares each score against `evals/baseline.json` and fails
  (exit 1) on a regression greater than 5 percentage points, or if a baselined
  suite produced no result.
- `evals/baseline.json` is the versioned regression anchor.

## Suites

| Suite | Gated score | Default? |
|---|---|---|
| `detector-phi` | F1 over HIPAA Safe Harbor identifier fixtures | always |
| `detector-secrets` | secrets-in-logs recall | always |
| `redaction-completeness` | detected-PHI removal rate | always |
| `injection-resistance` | honeypot-canary trip rate | always |
| `tool-arg-fuzzing` | hostile tool-arg refusal rate | always |
| `citation-correctness` | citation parser pass rate | always |
| `citation-live` | live chat citations resolve to real findings | `EVAL_LLM=1` |
| `agent-agreement` | triage severity agreement vs golden labels | `EVAL_LLM=1` |

The deterministic suites are credential-free and form the committed baseline.
Several detector/secret identifier classes are intentionally uncovered today;
the recorded scores capture that gap as a baseline (see `meta.per_class_recall`
/ `meta.per_kind_detected`), and closing them is tracked as M11 follow-up.

### Detector fixture corpus (production-shaped)

`src/evals/fixtures/phi.ts` carries two cohorts, tagged per fixture via `shape`:

- **clean** — short single-sentence lines (a readable smoke set).
- **json / kv / stacktrace / prose** — realistic messy cloud-log lines: JSON
  envelopes, key=value (logfmt), stack traces, and multi-identifier prose. Real
  logs embed identifiers inside structured wrappers, so a clean-only corpus
  over-states precision/recall. Each PHI span is labeled with its own Safe
  Harbor `identifier` so a single messy line can carry several classes and still
  attribute each to the right class in `meta.per_class_recall`;
  `meta.per_shape_recall` shows how recall holds up per log shape.

A labeled span may set `knownGap` when the detector is **deliberately** unable to
match it and the miss is an accepted trade-off (e.g. ISO-8601 dates are not
flagged because the date detector is slash-only to avoid drowning in routine log
timestamps). The detector-phi suite asserts that *every* false negative is a
recorded `knownGap`, so a new, unexplained miss fails the suite loudly even
though it stays inside the 5pt regression tolerance. The current `detector-phi`
baseline is **0.9908** (one accepted ISO-date gap); precision stays at 1.0
across the harder benign corpus.
