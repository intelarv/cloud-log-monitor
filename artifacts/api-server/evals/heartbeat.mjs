// Nightly eval-gate heartbeat / dead-man's switch (pure Node ESM).
//
// The problem this closes: with EVAL_NOTIFY_ON=always the nightly eval gate
// posts a daily all-green confirmation, so on-call learns the suites are
// healthy. But if the CronJob itself silently stops running — image pull
// failure, the schedule got disabled, a cluster/scheduler problem — it
// produces NO message at all. Absence of a message is exactly what on-call
// cannot see. notify.mjs can only speak when the job runs; it cannot speak
// about a job that never started.
//
// This module is a textbook dead-man's switch built from two halves:
//   --record : the nightly job calls this on EVERY completed run (pass OR
//              fail) to stamp "the nightly mechanism was alive at <now>" into
//              a durable store (the DB the nightly job already connects to).
//              Recording on failure too is deliberate: a failed run already
//              pages via notify.mjs, and the heartbeat is about run *liveness*
//              (did the job execute), not run *quality*.
//   --check  : a separate, more-frequent CronJob calls this. If the last
//              recorded heartbeat is older than the expected interval (+grace),
//              or there is no heartbeat at all, it posts a page-worthy alert
//              through the SAME CHANNEL_* config + severity gating as the eval
//              run alerts (reusing postToChannels from notify.mjs), so it lands
//              in the same place on-call already watches.
//
// Why the DB as the store: the nightly job already has DATABASE_URL + DB
// connectivity (the live suites need it), so a single tiny row is the lowest
// friction durable state that survives across pods/runs. The table is created
// idempotently here (CREATE TABLE IF NOT EXISTS) — it is an ops/liveness
// table, mutable by design and under no audit triggers, so it lives entirely
// in this CI-side script rather than the app's Drizzle schema.
//
// External leg (closes the cluster-down gap): both CronJobs run *inside* the
// cluster, so a total cluster/scheduler outage silences the in-cluster checker
// too — an in-cluster switch cannot report that the cluster it lives in is down.
// To cover that, the nightly job ALSO pings an external uptime / dead-man's
// switch service (healthchecks.io / Cronitor) when HEARTBEAT_PING_URL is set.
// That service fires its OWN alert when an expected ping is missed, so a
// cluster-down condition (which stops the nightly job from ever pinging) still
// pages from outside the cluster. The ping is env-gated (inert when unset) and
// best-effort: a failure to reach it is logged and swallowed, never changing
// the eval job's exit code — the same non-fatal posture as the DB record.
//
// Start / success / fail signals (closes the hung-run gap): a single ping fired
// only on completion lets the external monitor detect a run that never finished
// only after the whole grace window elapses, and cannot tell "started but hung"
// from "never scheduled". So the nightly job sends a START signal BEFORE the
// eval run (--start) and a SUCCESS-or-FAIL signal AFTER (--record). With the
// start signal recorded, the monitor knows a run began and can alert fast when
// the matching completion never arrives (a hung suite, an LLM call wedged past
// its timeout). A failed-but-alive run is signalled distinctly from a missed
// run so on-call can tell them apart. The exact URL shape follows the monitor's
// convention (HEARTBEAT_PING_STYLE): healthchecks.io uses path suffixes
// (<url>/start, <url>, <url>/fail); Cronitor uses a query state (?state=run |
// complete | fail).

import pg from "pg";
import {
  classifyOutcome,
  loadSummary,
  postToChannels,
  resolveHeartbeat,
  selectForSeverity,
  parseChannels,
} from "./notify.mjs";

const { Pool } = pg;

// Default max age (minutes) before a missing heartbeat pages: 26h. The nightly
// runs every 24h, so the threshold must exceed one interval + run duration +
// grace, otherwise the gap between two consecutive nightly runs would itself
// look stale. Operators tune via EVAL_HEARTBEAT_MAX_AGE_MINUTES to match their
// schedule.
export const DEFAULT_MAX_AGE_MINUTES = 26 * 60;

// A missing nightly confirmation is operationally page-worthy (someone must
// check why the job stopped) but is not a data-integrity incident, so — like a
// hard-fail in notify.mjs — it maps to "high". The same per-channel
// CHANNEL_*_MIN_SEVERITY gating therefore applies.
const HEARTBEAT_SEVERITY = "high";

// Default timeout (ms) for the external uptime ping. Kept short so a slow or
// unreachable monitor never stalls the nightly job; tunable via
// HEARTBEAT_PING_TIMEOUT_MS.
export const DEFAULT_PING_TIMEOUT_MS = 10000;

const HEARTBEAT_TABLE = "eval_gate_heartbeats";

const DDL = `CREATE TABLE IF NOT EXISTS ${HEARTBEAT_TABLE} (
  gate_name text PRIMARY KEY,
  last_success_at timestamptz NOT NULL,
  outcome text,
  updated_at timestamptz NOT NULL DEFAULT now()
)`;

/** Which gate this heartbeat tracks (single-valued for now). */
export function gateName(env = process.env) {
  const raw = (env.EVAL_HEARTBEAT_NAME ?? "nightly").trim();
  return raw || "nightly";
}

/** Parse EVAL_HEARTBEAT_MAX_AGE_MINUTES (default 26h). A non-positive or
 *  non-numeric value warns + falls back to the default so a typo can never
 *  silently disable the switch (e.g. setting it absurdly high). */
export function parseMaxAgeMinutes(env = process.env) {
  const raw = env.EVAL_HEARTBEAT_MAX_AGE_MINUTES;
  if (raw === undefined || String(raw).trim() === "") return DEFAULT_MAX_AGE_MINUTES;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.warn(
      `[eval-heartbeat] invalid EVAL_HEARTBEAT_MAX_AGE_MINUTES=${raw}; defaulting to ${DEFAULT_MAX_AGE_MINUTES}`,
    );
    return DEFAULT_MAX_AGE_MINUTES;
  }
  return n;
}

/** Age of a heartbeat in minutes, or null when there is no heartbeat. */
export function ageMinutes(lastSuccessAt, now = Date.now()) {
  if (!lastSuccessAt) return null;
  const ts = new Date(lastSuccessAt).getTime();
  if (Number.isNaN(ts)) return null;
  return (now - ts) / 60000;
}

/** A heartbeat is stale (→ page) when it is missing/unparseable, or older than
 *  the max age. */
export function isStale(lastSuccessAt, maxAgeMinutes, now = Date.now()) {
  const age = ageMinutes(lastSuccessAt, now);
  if (age === null) return true;
  return age > maxAgeMinutes;
}

/** Human-readable Slack body. Liveness metadata only — no scores, no PHI. */
export function buildHeartbeatText({ name, lastSuccessAt, maxAgeMinutes, now = Date.now() }) {
  const age = ageMinutes(lastSuccessAt, now);
  const last = lastSuccessAt ? new Date(lastSuccessAt).toISOString() : "never recorded";
  const ageStr = age === null ? "n/a" : `${Math.round(age)}min`;
  return [
    `[ALERT ${HEARTBEAT_SEVERITY}] eval-gate.heartbeat_missing — no nightly eval confirmation for gate '${name}' in over ${maxAgeMinutes}min`,
    `last success: ${last} (age: ${ageStr}); expected within ${maxAgeMinutes}min`,
    "cause: the nightly eval CronJob has not completed (image pull failure, schedule disabled, or cluster issue). Its silence produces no other alert — this dead-man's switch is the only signal.",
  ].join("\n");
}

/** Signed-webhook payload. Liveness metadata only — no scores, no PHI. */
export function buildHeartbeatPayload({ name, lastSuccessAt, maxAgeMinutes, now = Date.now() }) {
  return {
    kind: "eval_gate_heartbeat_missing",
    severity: HEARTBEAT_SEVERITY,
    gateName: name,
    lastSuccessAt: lastSuccessAt ? new Date(lastSuccessAt).toISOString() : null,
    ageMinutes: ageMinutes(lastSuccessAt, now),
    maxAgeMinutes,
    occurredAt: new Date(now).toISOString(),
  };
}

/** Decide on a heartbeat and, if stale, post the alert to the configured
 *  channels. Pure w.r.t. the DB — it takes the already-fetched `lastSuccessAt`
 *  and an injectable `fetchImpl` so it is unit-testable without a database.
 *  Returns `{ stale, skipped, sent, severity, ageMinutes, maxAgeMinutes }`. */
export async function evaluateHeartbeat({
  env = process.env,
  name = gateName(env),
  lastSuccessAt,
  maxAgeMinutes = parseMaxAgeMinutes(env),
  now = Date.now(),
  fetchImpl = fetch,
} = {}) {
  const age = ageMinutes(lastSuccessAt, now);
  if (!isStale(lastSuccessAt, maxAgeMinutes, now)) {
    console.log(
      `[eval-heartbeat] gate '${name}' healthy (age ${Math.round(age)}min <= ${maxAgeMinutes}min); no alert`,
    );
    // Liveness recovery: clear any open "went quiet" page the staleness trigger
    // raised. Keyed on the SAME stable dedup_key, so a recovered check folds the
    // prior incident closed automatically — no hand-closing a self-healed page.
    // Inert (empty sent) when PagerDuty is not configured; never throws.
    const { sent } = await resolveHeartbeat({ env, fetchImpl });
    return {
      stale: false,
      skipped: sent.length === 0,
      sent,
      severity: HEARTBEAT_SEVERITY,
      ageMinutes: age,
      maxAgeMinutes,
    };
  }

  console.warn(
    `[eval-heartbeat] gate '${name}' STALE (last success ${
      lastSuccessAt ? new Date(lastSuccessAt).toISOString() : "never"
    }, age ${age === null ? "n/a" : `${Math.round(age)}min`} > ${maxAgeMinutes}min); alerting`,
  );

  // Surface why nothing will be sent even though we are stale, so an operator
  // reading the logs knows the alert was suppressed by config (not lost).
  if (parseChannels(env).length === 0) {
    console.warn(
      "[eval-heartbeat] STALE but no channel configured — on-call will NOT be paged; configure CHANNEL_* on the heartbeat CronJob",
    );
  } else if (selectForSeverity(parseChannels(env), HEARTBEAT_SEVERITY).length === 0) {
    console.warn(
      `[eval-heartbeat] STALE but no channel accepts '${HEARTBEAT_SEVERITY}' severity — check CHANNEL_*_MIN_SEVERITY`,
    );
  }

  const text = buildHeartbeatText({ name, lastSuccessAt, maxAgeMinutes, now });
  const payload = buildHeartbeatPayload({ name, lastSuccessAt, maxAgeMinutes, now });
  const { skipped, sent } = await postToChannels({
    env,
    severity: HEARTBEAT_SEVERITY,
    text,
    payload,
    fetchImpl,
  });
  return { stale: true, skipped, sent, severity: HEARTBEAT_SEVERITY, ageMinutes: age, maxAgeMinutes };
}

/** The external uptime / dead-man's-switch ping URL (healthchecks.io /
 *  Cronitor), or null when unset. Env-gated: with no URL the external leg is
 *  fully inert. */
export function externalPingUrl(env = process.env) {
  const raw = (env.HEARTBEAT_PING_URL ?? "").trim();
  return raw || null;
}

/** Validate the external outage-alert ping config (HEARTBEAT_PING_URL) so a
 *  misconfigured dead-man's switch is caught LOUDLY instead of silently doing
 *  nothing. Without this, a typo'd or non-http(s) URL fails the `fetch` at run
 *  time as a "non-fatal network error" — indistinguishable from a transient
 *  blip — so the cluster-down outage alert would never actually fire and nobody
 *  would know until an outage went unnoticed. Returns
 *  `{ configured, valid, url, reason }`:
 *    - unset      → { configured:false, valid:false, url:null,  reason:null } (intentionally inert)
 *    - bad URL    → { configured:true,  valid:false, url:<raw>, reason:"..." } (misconfigured — surfaced loudly)
 *    - good URL   → { configured:true,  valid:true,  url:<raw>, reason:null }
 *  Pure (no I/O). */
export function validateExternalPing(env = process.env) {
  const raw = (env.HEARTBEAT_PING_URL ?? "").trim();
  if (!raw) return { configured: false, valid: false, url: null, reason: null };
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { configured: true, valid: false, url: raw, reason: "not a valid absolute URL" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      configured: true,
      valid: false,
      url: raw,
      reason: `unsupported scheme '${parsed.protocol}' (expected http/https)`,
    };
  }
  return { configured: true, valid: true, url: raw, reason: null };
}

/** Which monitor convention to use when shaping the start/success/fail ping
 *  URL. healthchecks.io uses path suffixes; Cronitor uses a `state` query.
 *  Default is `healthchecks`; an unknown value warns + falls back rather than
 *  silently breaking the signal. */
export function pingStyle(env = process.env) {
  const raw = (env.HEARTBEAT_PING_STYLE ?? "healthchecks").trim().toLowerCase();
  if (raw === "cronitor") return "cronitor";
  if (raw === "" || raw === "healthchecks" || raw === "healthchecksio" || raw === "healthchecks.io") {
    return "healthchecks";
  }
  console.warn(`[eval-heartbeat] unknown HEARTBEAT_PING_STYLE=${raw}; defaulting to healthchecks`);
  return "healthchecks";
}

/** Shape the external ping URL for a run stage given the monitor convention.
 *  Pure + style-aware:
 *    healthchecks: start → <url>/start, success → <url>, fail → <url>/fail
 *    cronitor:     start → ?state=run, success → ?state=complete, fail → ?state=fail
 *  A `success` ping for healthchecks is the bare URL (its "OK" check-in). */
export function buildPingUrl(baseUrl, stage = "success", style = "healthchecks") {
  if (style === "cronitor") {
    const state = stage === "start" ? "run" : stage === "fail" ? "fail" : "complete";
    const sep = baseUrl.includes("?") ? "&" : "?";
    return `${baseUrl}${sep}state=${state}`;
  }
  // healthchecks.io: bare URL is the success/OK check-in; start/fail are suffixes.
  if (stage === "success") return baseUrl;
  const trimmed = baseUrl.replace(/\/+$/, "");
  return `${trimmed}/${stage}`;
}

/** Parse HEARTBEAT_PING_TIMEOUT_MS (default 10s). A non-positive/non-numeric
 *  value falls back to the default rather than disabling the timeout. */
export function parsePingTimeoutMs(env = process.env) {
  const raw = env.HEARTBEAT_PING_TIMEOUT_MS;
  if (raw === undefined || String(raw).trim() === "") return DEFAULT_PING_TIMEOUT_MS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.warn(
      `[eval-heartbeat] invalid HEARTBEAT_PING_TIMEOUT_MS=${raw}; defaulting to ${DEFAULT_PING_TIMEOUT_MS}`,
    );
    return DEFAULT_PING_TIMEOUT_MS;
  }
  return n;
}

/** Ping the external uptime monitor so a missed ping (e.g. the whole cluster is
 *  down and the nightly job never ran) pages on-call from OUTSIDE the cluster.
 *  `stage` selects the run phase the monitor sees — "start" (a run began),
 *  "success" (a run completed cleanly), or "fail" (a run ran but failed) — and
 *  is shaped onto the URL per the monitor's convention (HEARTBEAT_PING_STYLE).
 *  A recorded "start" with no matching "success"/"fail" is exactly what lets the
 *  monitor flag a hung run, distinctly from one that never scheduled.
 *  Inert when HEARTBEAT_PING_URL is unset. Best-effort: any failure (network
 *  error, timeout, non-2xx) is logged and swallowed — the caller treats this as
 *  non-fatal, exactly like the DB record. Returns
 *  `{ pinged, stage, skipped?, ok?, status?, error? }`. */
export async function pingExternalHeartbeat({
  env = process.env,
  fetchImpl = fetch,
  timeoutMs = parsePingTimeoutMs(env),
  stage = "success",
} = {}) {
  const cfg = validateExternalPing(env);
  if (!cfg.configured) {
    return { pinged: false, skipped: true, stage };
  }
  if (!cfg.valid) {
    // Misconfigured outage alert: surface it loudly EVERY run rather than letting
    // the bad URL fail silently as a "non-fatal network error". The external
    // dead-man's switch will NOT fire while this is broken, so a cluster-down
    // outage would go unnoticed. Returned (not thrown) so it stays non-fatal.
    console.error(
      `[eval-heartbeat] MISCONFIGURED external outage alert: HEARTBEAT_PING_URL ${cfg.reason} — the external dead-man's switch will NOT fire, so a cluster-down outage would go unnoticed; fix HEARTBEAT_PING_URL`,
    );
    return { pinged: false, misconfigured: true, reason: cfg.reason, stage };
  }
  const url = buildPingUrl(cfg.url, stage, pingStyle(env));
  let signal;
  try {
    signal = AbortSignal.timeout(timeoutMs);
  } catch {
    signal = undefined;
  }
  try {
    const res = await fetchImpl(url, { method: "GET", signal });
    if (!res.ok) {
      console.warn(
        `[eval-heartbeat] external uptime ping (${stage}) returned HTTP ${res.status} (non-fatal)`,
      );
      return { pinged: true, ok: false, status: res.status, stage };
    }
    console.log(`[eval-heartbeat] external uptime ping (${stage}) sent`);
    return { pinged: true, ok: true, status: res.status, stage };
  } catch (err) {
    console.warn(
      `[eval-heartbeat] external uptime ping (${stage}) failed (non-fatal): ${err?.message ?? err}`,
    );
    return { pinged: true, ok: false, error: String(err?.message ?? err), stage };
  }
}

function newPool(env = process.env) {
  if (!env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not set — the heartbeat store needs a database connection");
  }
  return new Pool({ connectionString: env.DATABASE_URL });
}

/** --record: stamp the heartbeat for the current run. Reads the gate verdict
 *  (if any) only to label the recorded outcome; records UNCONDITIONALLY of
 *  pass/fail because the heartbeat tracks run liveness, not run quality. */
export async function recordHeartbeat({ env = process.env, evalsDir, outcome, exitCode, fetchImpl = fetch } = {}) {
  const name = gateName(env);
  const resolvedOutcome = outcome ?? classifyOutcome(loadSummary(evalsDir));

  // The external signal distinguishes a failed-but-alive run ("fail") from a
  // clean one ("success") so the monitor reflects which happened. The gate exit
  // code is authoritative when passed (it catches a crash before any summary is
  // written); otherwise fall back to the classified outcome.
  const failed =
    exitCode !== undefined && exitCode !== null
      ? Number(exitCode) !== 0
      : resolvedOutcome === "failed";
  const stage = failed ? "fail" : "success";

  // In-cluster leg: stamp the durable row. Wrapped so a DB failure cannot stop
  // the external leg below — the two legs are independent dead-man's switches.
  let recorded = false;
  try {
    const pool = newPool(env);
    try {
      await pool.query(DDL);
      await pool.query(
        `INSERT INTO ${HEARTBEAT_TABLE} (gate_name, last_success_at, outcome, updated_at)
         VALUES ($1, now(), $2, now())
         ON CONFLICT (gate_name)
         DO UPDATE SET last_success_at = now(), outcome = EXCLUDED.outcome, updated_at = now()`,
        [name, resolvedOutcome],
      );
      recorded = true;
      console.log(`[eval-heartbeat] recorded heartbeat for gate '${name}' (outcome ${resolvedOutcome})`);
    } finally {
      await pool.end();
    }
  } catch (err) {
    console.error(`[eval-heartbeat] DB heartbeat record failed (non-fatal): ${err?.message ?? err}`);
  }

  // External leg: ping the external uptime monitor so a cluster-down condition
  // (the nightly job never ran → no ping) still pages from outside the cluster.
  // The stage (success/fail) lets the monitor reflect a failed-but-alive run.
  const ping = await pingExternalHeartbeat({ env, fetchImpl, stage });

  return { recorded, gateName: name, outcome: resolvedOutcome, ping };
}

/** --start: ping the external monitor that a nightly run is BEGINNING, before
 *  the eval suite executes. Purely the external leg — no DB row is stamped here,
 *  because the in-cluster checker tracks completion liveness, while the start
 *  signal exists so the external monitor can flag a run that began but never
 *  reported completion (a hung suite). Inert + non-fatal like the record leg. */
export async function startHeartbeat({ env = process.env, fetchImpl = fetch } = {}) {
  const ping = await pingExternalHeartbeat({ env, fetchImpl, stage: "start" });
  return { gateName: gateName(env), ping };
}

/** --check: fetch the heartbeat and page if stale. */
export async function checkHeartbeat({ env = process.env, now = Date.now(), fetchImpl = fetch } = {}) {
  const name = gateName(env);
  const pool = newPool(env);
  let lastSuccessAt = null;
  try {
    await pool.query(DDL);
    const res = await pool.query(
      `SELECT last_success_at FROM ${HEARTBEAT_TABLE} WHERE gate_name = $1`,
      [name],
    );
    lastSuccessAt = res.rows[0]?.last_success_at ?? null;
  } finally {
    await pool.end();
  }
  return evaluateHeartbeat({ env, name, lastSuccessAt, now, fetchImpl });
}

// CLI entrypoint. `--start` is invoked by deploy/scripts/eval-gate-llm.sh BEFORE
// the eval run; `--record` after every completed run (carrying --exit-code so a
// fail is signalled distinctly); `--check` by the heartbeat CronJob.
const isMain =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const args = process.argv.slice(2);
  const mode = args.includes("--start")
    ? "start"
    : args.includes("--record")
      ? "record"
      : args.includes("--check")
        ? "check"
        : null;
  const exitArg = args.find((a) => a.startsWith("--exit-code="));
  const exitCode = exitArg ? Number(exitArg.split("=")[1]) : undefined;
  if (mode === null) {
    console.error("[eval-heartbeat] usage: heartbeat.mjs --start | --record [--exit-code=N] | --check");
    process.exitCode = 2;
  } else if (mode === "start") {
    // The start ping must never block or fail the eval run that follows it, so a
    // start failure is logged and swallowed — same non-fatal posture as record.
    startHeartbeat()
      .catch((err) => console.error(`[eval-heartbeat] start failed (non-fatal): ${err?.message ?? err}`))
      .finally(() => {
        process.exitCode = 0;
      });
  } else if (mode === "record") {
    // Recording must never change the eval job's exit code (the gate result is
    // the source of truth), so a record failure is logged and swallowed.
    recordHeartbeat({ exitCode })
      .catch((err) => console.error(`[eval-heartbeat] record failed (non-fatal): ${err?.message ?? err}`))
      .finally(() => {
        process.exitCode = 0;
      });
  } else {
    // The checker IS the safety mechanism: surface its own failures (DB
    // unreachable, etc.) via a non-zero exit so the CronJob's failed-history
    // and cluster monitoring catch a broken switch.
    checkHeartbeat()
      .then((r) => {
        process.exitCode = 0;
        // A send was attempted (not config-suppressed) but at least one channel
        // failed. Two cases share this shape and both must surface non-zero:
        //   stale  → we tried to PAGE the "went quiet" incident and it failed.
        //   healthy → we tried to RESOLVE/auto-clear that page and it failed.
        // A swallowed failed-resolve would leave the page lingering open with
        // nobody aware the auto-clear never landed, so it gets the same
        // visibility as a failed page: a non-zero exit the CronJob's
        // failed-history and cluster monitoring catch.
        if (!r.skipped && r.sent.some((s) => !s.ok)) {
          process.exitCode = 1;
        }
      })
      .catch((err) => {
        console.error(`[eval-heartbeat] check failed: ${err?.message ?? err}`);
        process.exitCode = 1;
      });
  }
}
