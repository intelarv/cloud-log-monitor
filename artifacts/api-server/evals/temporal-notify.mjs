// Nightly Temporal live-cluster integration gate notifier (pure Node ESM).
//
// The nightly Temporal integration job (.github/workflows/temporal-integration.yml)
// runs the live-cluster harness (temporal-integration.test.ts against a REAL
// `temporal server start-dev`) as a standing gate. But a red nightly run only
// surfaces in the GitHub Actions tab — nobody is paged, so a regression in the
// durable-orchestration backend can sit unnoticed until someone happens to look.
//
// This module posts a concise failure alert to the SAME channels the eval gate
// + the application's finding-alert pipeline use (Slack incoming-webhook /
// generic HMAC-signed webhook / PagerDuty Events API v2). It deliberately
// REUSES notify.mjs's postToChannels primitive rather than reinventing the
// channel adapters, so the signing scheme, the per-channel
// CHANNEL_*_MIN_SEVERITY gating, and the inert-when-unconfigured posture are all
// shared, not duplicated. (The webhook signing scheme is locked to the app's
// adapter by the cross-check unit test, so the two cannot drift.)
//
// Severity: a failed live-cluster gate is operationally page-worthy but not a
// data-integrity incident, so — exactly like a hard-fail in the eval-gate
// notifier — it maps to "high". The same per-channel severity gating therefore
// applies: a channel pinned to CHANNEL_*_MIN_SEVERITY=critical receives nothing,
// and one pinned to high/warning is paged.
//
// Scope: this only POSTS on a FAILED run (non-zero exit code). The workflow
// restricts invocation to the nightly schedule (manual workflow_dispatch and PR
// runs never page — a red result there is already visible to whoever triggered
// it), so this script trusts its caller and does not itself inspect the trigger.
//
// PagerDuty dedup: uses a distinct STABLE key (defaultTemporalDedupKey,
// "temporal-integration-nightly") so a failing Temporal gate is its own incident
// — separate from the eval-gate run page and the dead-man's-switch heartbeat
// page — and re-runs of a still-red gate fold into one incident instead of
// spamming a new page each night.
//
// No PHI by construction: the body carries only the gate name + which job failed
// (CI infra liveness, never log/finding content). Inert when no channel is
// configured. Never throws and never changes the job's exit code — the workflow
// step's own status is the source of truth for the run result.

import { defaultTemporalDedupKey, postToChannels } from "./notify.mjs";

// A failed live-cluster gate is page-worthy but not a data-integrity incident,
// so it maps to "high" — the same mapping the eval-gate notifier uses for a
// hard-fail, so the same CHANNEL_*_MIN_SEVERITY gating applies.
const TEMPORAL_SEVERITY = "high";

// PagerDuty `source` label so the incident is attributed to this gate (distinct
// from the eval-gate/heartbeat source). PagerDuty's `source` is a free-text
// origin descriptor — not used for routing or dedup — but a correct label helps
// on-call triage at a glance.
const PAGERDUTY_SOURCE = "phi-audit temporal-integration.nightly";

const ALERT_KIND = "temporal_integration_failure";

/** The gate name this notifier tracks (single-valued for now); overridable so a
 *  future second Temporal gate can label its alerts distinctly. */
export function gateName(env = process.env) {
  const raw = (env.TEMPORAL_GATE_NAME ?? "nightly").trim();
  return raw || "nightly";
}

/** Concise human-readable Slack/text body. CI liveness metadata only — no PHI.
 *  Names the gate + the page-worthy cause so on-call can act without opening the
 *  Actions tab. */
export function buildTemporalText({ name, exitCode, now = Date.now() } = {}) {
  return [
    `[ALERT ${TEMPORAL_SEVERITY}] temporal-integration.nightly_failed — nightly Temporal live-cluster integration gate '${name}' FAILED (exit ${exitCode})`,
    "cause: the live-cluster harness (test:temporal — real `temporal server start-dev` + native worker) went red on the nightly schedule. This gate guards the durable supervisor backend (WORKFLOW_ENGINE=temporal): the Triage→Verifier activity sequence, duplicate-emit dedupe, and worker-crash resume.",
    "action: check the GitHub Actions 'Temporal integration (live cluster)' run for the failing case before relying on the Temporal backend.",
    `occurred: ${new Date(now).toISOString()}`,
  ].join("\n");
}

/** Signed-webhook payload. CI liveness metadata only — no scores, no PHI. */
export function buildTemporalPayload({ name, exitCode, now = Date.now() } = {}) {
  return {
    kind: ALERT_KIND,
    severity: TEMPORAL_SEVERITY,
    gateName: name,
    exitCode,
    occurredAt: new Date(now).toISOString(),
  };
}

/** Parse the gate exit code from `--exit-code=N` (CLI) or an explicit value.
 *  An absent/garbage value is treated as a failure (1) — we only run this on a
 *  failed step, so erring toward "page" is the safe default. */
export function parseExitCode(argv = process.argv) {
  const arg = argv.find((a) => a.startsWith("--exit-code="));
  if (!arg) return 1;
  const n = Number(arg.split("=")[1]);
  return Number.isFinite(n) ? n : 1;
}

/** Post the Temporal-gate failure alert to every configured + severity-eligible
 *  channel, reusing the shared CHANNEL_* posting primitive. Only a non-zero
 *  exit code (a failed run) posts; a passing run is a no-op. Inert when nothing
 *  is configured or no channel accepts "high". Never throws — a notification
 *  failure must not change the job's exit code (the workflow step owns that).
 *  Returns `{ skipped, sent, severity, exitCode }`. */
export async function notifyTemporalGate({
  env = process.env,
  exitCode,
  name = gateName(env),
  fetchImpl = fetch,
  now = Date.now(),
} = {}) {
  if (exitCode === 0) {
    console.log(`[temporal-notify] gate '${name}' passed (exit 0); no alert`);
    return { skipped: true, sent: [], severity: TEMPORAL_SEVERITY, exitCode };
  }

  console.warn(
    `[temporal-notify] gate '${name}' FAILED (exit ${exitCode}); dispatching alert to configured channels`,
  );

  const text = buildTemporalText({ name, exitCode, now });
  const payload = buildTemporalPayload({ name, exitCode, now });
  const { skipped, sent } = await postToChannels({
    env,
    severity: TEMPORAL_SEVERITY,
    text,
    payload,
    fetchImpl,
    pagerDutyDedupKey: defaultTemporalDedupKey(),
    pagerDutySource: PAGERDUTY_SOURCE,
  });
  return { skipped, sent, severity: TEMPORAL_SEVERITY, exitCode };
}

// CLI entrypoint: invoked by the nightly Temporal workflow ONLY when the live
// integration step failed (the workflow gates this on a scheduled run, so manual
// / PR re-runs never page). The exit code is passed through for the alert body.
const isMain =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const exitCode = parseExitCode();
  notifyTemporalGate({ exitCode })
    .catch((err) => {
      console.error(`[temporal-notify] fatal: ${err?.message ?? err}`);
    })
    .finally(() => {
      // Always exit 0: the workflow step's own status is the source of truth for
      // the job result; the notifier must never flip a red run green or vice versa.
      process.exitCode = 0;
    });
}
