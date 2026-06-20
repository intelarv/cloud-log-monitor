// Nightly eval-gate channel notifier (pure Node ESM; no TS runner needed).
//
// The nightly AI-backed eval gate (deploy/scripts/eval-gate-llm.sh) only
// surfaces its verdict as the job's exit status + pod logs, so a regression is
// easy to miss until someone checks the cluster. This module posts a concise
// pass/fail summary to the SAME channels the application's finding-alert
// pipeline uses (Slack incoming-webhook / generic HMAC-signed webhook /
// PagerDuty Events API v2), reusing the same env config and the same
// severity-gating semantics as src/lib/channels/router.ts.
//
// EVAL_NOTIFY_ON (fail | warn | always) controls which run outcomes post:
//   - fail    (default) — only a hard-fail posts (prior behavior).
//   - warn    — hard-fails AND passing-with-warnings runs post.
//   - always  — also posts an all-green confirmation, so silence is never
//               ambiguous to on-call.
// The outcome maps to a severity (failed → high, warned/clean → warning) so the
// SAME per-channel CHANNEL_*_MIN_SEVERITY gating still applies: a warning-class
// confirmation never reaches a channel pinned to high/critical.
//
// Why a standalone ESM notifier instead of dispatchAlertFromLedger():
//   - The eval gate runs OUTSIDE the application runtime (a CI/cron job). There
//     is no LedgerEntry to dispatch and no DB write path to hang the alert off.
//   - gate.mjs (which computes the verdict) is pure ESM and cannot import the
//     TypeScript channel adapters. So this mirrors their *config* + *severity
//     gating* + *webhook signing scheme* rather than importing them. The
//     signing scheme is locked to src/lib/channels/adapters/webhook.ts by a
//     cross-check unit test (eval-gate-notify.test.ts) so the two cannot drift.
//   - The ChannelEnvelope contract (src/lib/channels/types.ts) is a deliberate
//     allow-list with no free-text field — it cannot carry "suite scores + which
//     check tripped". The eval summary is scores + suite names only (synthetic
//     fixtures, no PHI by construction), so it is safe to send a richer body
//     here, outside that PHI-hard-gated envelope.
//
// Inert when no channel is configured — matches the existing adapter behavior.

import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac } from "node:crypto";

// Mirrors SEVERITY_RANK in src/lib/channels/router.ts.
const SEVERITY_RANK = { warning: 1, high: 2, critical: 3 };

// Severity per run outcome. A hard-fail is operationally page-worthy but not a
// data-integrity incident, so it maps to "high"; a passing run (with or without
// non-fatal warnings) maps to "warning". The same severity gating the router
// applies to finding alerts therefore still applies here: a channel set to
// CHANNEL_*_MIN_SEVERITY=high never receives the warning-class confirmations,
// and a critical-only channel receives nothing from the eval gate.
const SEVERITY_BY_OUTCOME = { failed: "high", warned: "warning", clean: "warning" };

// Default severity used when callers don't pass one (kept at the historical
// "high" so existing severity-gating tests/behavior are unchanged).
const DEFAULT_GATE_SEVERITY = "high";

// EVAL_NOTIFY_ON trigger levels and the outcomes each one admits. An outcome is
// notified when its level is <= the configured trigger level.
const NOTIFY_LEVEL = { fail: 0, warn: 1, always: 2 };
const OUTCOME_LEVEL = { failed: 0, warned: 1, clean: 2 };

const OUTCOME_KIND = {
  failed: "eval_gate_failure",
  warned: "eval_gate_warning",
  clean: "eval_gate_ok",
};

// Webhook payload `kind` for the Slack/webhook recovery note posted when a
// passing run follows a prior fail (the parallel of the PagerDuty auto-resolve).
const RECOVERY_KIND = "eval_gate_recovered";

// Gate suite statuses (set by gate.mjs) that count as a failing suite. Used to
// record which suites were red in a run's history so the next passing run can
// name which ones came back green.
const FAILING_STATUSES = new Set(["FAIL", "missing", "BELOW_FLOOR"]);

const OUTCOME_HEADER = {
  failed: "eval-gate.nightly_failed — nightly AI eval gate FAILED",
  warned: "eval-gate.nightly_warned — nightly AI eval gate PASSED with warnings",
  clean: "eval-gate.nightly_ok — nightly AI eval gate PASSED (all suites green)",
};

// Slack Block Kit presentation. The one-word headline lets on-call distinguish
// failed / warned / clean at a glance; the colored attachment bar reinforces it.
const OUTCOME_HEADLINE = { failed: "FAILED", warned: "WARNINGS", clean: "PASSED" };
const OUTCOME_EMOJI = {
  failed: ":red_circle:",
  warned: ":large_yellow_circle:",
  clean: ":large_green_circle:",
};
// Attachment side-bar color per outcome (Slack accepts hex or good|warning|danger).
const OUTCOME_COLOR = { failed: "#d7263d", warned: "#f5a623", clean: "#2eb886" };

// PagerDuty Events API v2 default endpoint. Operators in the EU region (or
// with a custom proxy) override via CHANNEL_PAGERDUTY_EVENTS_URL.
const PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue";

// Map our internal severity onto PagerDuty's Events API v2 severity enum
// (`critical | error | warning | info`). MUST stay in lockstep with
// toPagerDutySeverity() in src/lib/channels/adapters/pagerduty.ts. `high`
// has no PagerDuty equivalent, so it maps to `error`.
const PAGERDUTY_SEVERITY = { warning: "warning", high: "error", critical: "critical" };

// Rolling score-history persistence (M11 trend indicator). Each nightly run
// appends its per-suite scores here so the next run can show on-call the
// direction + delta vs. the previous run — slow erosion that stays just inside
// the 5pt regression tolerance is invisible from a single night's snapshot but
// obvious as a multi-night downward trend.
//
// Lives at evals/score-history.json, a sibling of evals/results/. It is NOT in
// results/ because `pnpm run eval` does `rm -rf evals/results` on every run; the
// history must survive across runs. Like the per-run result files it is run
// output (gitignored), not a hand-maintained anchor like baseline.json. In an
// ephemeral CI/cron pod, mount a durable path here (or a small volume) so the
// trend persists across nightly invocations.
const HISTORY_FILENAME = "score-history.json";
const HISTORY_VERSION = 1;
// How many recent runs to retain. Enough to eyeball a slow slide without the
// file growing unbounded; overridable via EVAL_HISTORY_LIMIT.
const DEFAULT_HISTORY_LIMIT = 30;

// Trend glyphs. Scores are "higher is better", so ▲ = improvement, ▼ = a drop
// (the one on-call cares about), ▬ = unchanged. A suite with no prior run is
// labeled "new" rather than shown as flat.
const TREND_GLYPH = { up: "▲", down: "▼", flat: "▬" };

/** Classify a gate verdict into one of failed | warned | clean. A non-ok
 *  verdict is always "failed"; an ok verdict with any non-fatal gate warnings
 *  (e.g. live suites that ran without a baseline, or below-tolerance drops) is
 *  "warned"; otherwise "clean". */
export function classifyOutcome(summary) {
  if (!summary?.ok) return "failed";
  return (summary.warnings?.length ?? 0) > 0 ? "warned" : "clean";
}

function round1(n) {
  return Math.round(n * 10) / 10;
}

/** Resolve the rolling-history retention count from EVAL_HISTORY_LIMIT
 *  (default 30). A non-positive / non-integer value falls back to the default. */
export function historyLimit(env = process.env) {
  const raw = env.EVAL_HISTORY_LIMIT;
  const n = raw !== undefined && raw.trim() !== "" ? Number(raw) : NaN;
  return Number.isInteger(n) && n > 0 ? n : DEFAULT_HISTORY_LIMIT;
}

/** Names of suites the gate counted as failing this run (status FAIL / missing /
 *  BELOW_FLOOR), sorted. Recorded in the run history so the next passing run can
 *  name which suites came back green. Pure. */
export function failingSuites(summary) {
  const out = [];
  const suites = summary?.suites ?? {};
  for (const [name, s] of Object.entries(suites)) {
    if (FAILING_STATUSES.has(s?.status)) out.push(name);
  }
  return out.sort();
}

/** Extract the `{ suite: score }` map from a gate verdict, keeping only suites
 *  that actually produced a numeric score this run (a "missing" baselined suite
 *  has no score and is omitted). */
export function extractScores(summary) {
  const scores = {};
  const suites = summary?.suites ?? {};
  for (const [name, s] of Object.entries(suites)) {
    if (typeof s?.score === "number") scores[name] = s.score;
  }
  return scores;
}

/** Load the rolling run history (oldest → newest). Returns [] when the file is
 *  absent or unparseable — a missing history just means "no trend yet", never an
 *  error. */
export function loadHistory(evalsDir = EVALS_DIR) {
  const p = join(evalsDir, HISTORY_FILENAME);
  if (!existsSync(p)) return [];
  try {
    const data = JSON.parse(readFileSync(p, "utf8"));
    return Array.isArray(data?.runs) ? data.runs : [];
  } catch (err) {
    console.warn(`[eval-notify] could not parse ${HISTORY_FILENAME}: ${err?.message ?? err}`);
    return [];
  }
}

/** The most recent prior run's `{ suite: score }` map, or null when there is no
 *  history to compare against. */
export function previousScores(history) {
  if (!Array.isArray(history) || history.length === 0) return null;
  return history[history.length - 1]?.scores ?? null;
}

/** The most recent prior run record (full object incl. `outcome` / `failed`), or
 *  null when there is no history. Used to detect a fail→pass recovery. */
export function previousRun(history) {
  if (!Array.isArray(history) || history.length === 0) return null;
  return history[history.length - 1] ?? null;
}

/** Per-suite trend vs. the previous run: direction (up | down | flat | new) and
 *  the rounded point delta. A suite with no prior score is "new". Pure. */
export function computeTrends(currentSuites = {}, prevScores = null) {
  const trends = {};
  for (const [name, s] of Object.entries(currentSuites)) {
    if (typeof s?.score !== "number") continue;
    const prev = prevScores?.[name];
    if (typeof prev !== "number") {
      trends[name] = { direction: "new", deltaPt: 0, prev: null };
      continue;
    }
    const deltaPt = round1((s.score - prev) * 100);
    const direction = deltaPt > 0 ? "up" : deltaPt < 0 ? "down" : "flat";
    trends[name] = { direction, deltaPt, prev };
  }
  return trends;
}

/** Render a single suite's trend as a compact suffix, e.g. " ▼ -1.2pt",
 *  " ▲ +0.5pt", " ▬ ±0.0pt", or " (new)". Empty string when no trend is known. */
export function fmtTrend(trend) {
  if (!trend) return "";
  if (trend.direction === "new") return " (new)";
  const d = trend.deltaPt;
  const signed = d > 0 ? `+${d.toFixed(1)}` : d < 0 ? d.toFixed(1) : `±${(0).toFixed(1)}`;
  return ` ${TREND_GLYPH[trend.direction]} ${signed}pt`;
}

// --- #23 per-suite score sparkline. A single night's ▲/▼ delta shows direction
// but not shape; a compact sparkline over the last N runs lets on-call see at a
// glance whether a suite is steadily eroding, recovering, or just noisy. The
// glyphs are scaled across the window's own min..max so small movements stay
// visible rather than collapsing to a flat line.
const SPARK_TICKS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/** Render an array of [0..1] scores as a unicode block sparkline, scaled across
 *  the window's own min..max (so a perfectly flat window renders as a full bar,
 *  never all-min). Non-finite entries are dropped. "" for an empty window. Pure. */
export function sparkline(scores = []) {
  const nums = (Array.isArray(scores) ? scores : []).filter(
    (n) => typeof n === "number" && Number.isFinite(n),
  );
  if (nums.length === 0) return "";
  const min = Math.min(...nums);
  const max = Math.max(...nums);
  const span = max - min;
  return nums
    .map((n) => {
      if (span === 0) return SPARK_TICKS[SPARK_TICKS.length - 1];
      const idx = Math.round(((n - min) / span) * (SPARK_TICKS.length - 1));
      return SPARK_TICKS[idx];
    })
    .join("");
}

/** Per-suite sparkline of the last `maxPoints` runs (history, chronological)
 *  PLUS this run's score appended last. Only suites that scored this run get a
 *  sparkline, and only when there are at least two points to draw a shape from.
 *  Returns `{ suite: "▁▃▅█" }`. Pure. */
export function computeSparklines(history = [], currentSuites = {}, maxPoints = 12) {
  const out = {};
  const runs = Array.isArray(history) ? history : [];
  for (const [name, s] of Object.entries(currentSuites)) {
    if (typeof s?.score !== "number") continue;
    const series = [];
    for (const run of runs) {
      const v = run?.scores?.[name];
      if (typeof v === "number") series.push(v);
    }
    series.push(s.score);
    const window = series.slice(-Math.max(2, maxPoints));
    if (window.length >= 2) out[name] = sparkline(window);
  }
  return out;
}

/** Render a suite's sparkline as a compact suffix, e.g. "  ▁▃▅█". "" when there
 *  is no sparkline for the suite. Pure. */
export function fmtSparkline(spark) {
  return spark ? `  ${spark}` : "";
}

// --- #24 multi-night downward-drift warning. Slow erosion that stays inside the
// per-run regression tolerance is invisible night-to-night but is a real quality
// regression over a week. When a suite's score drops for EVAL_DRIFT_RUNS
// consecutive runs (default 3) AND the cumulative drop clears
// EVAL_DRIFT_MIN_DROP_PT points (default 0 = any sustained slide), surface it as
// a warning so on-call is told before the slide finally trips the gate.
const DEFAULT_DRIFT_RUNS = 3;
const DEFAULT_DRIFT_MIN_DROP_PT = 0;

/** Resolve drift config from env. EVAL_DRIFT_RUNS = consecutive drops required
 *  (default 3; a value < 2 disables drift detection). EVAL_DRIFT_MIN_DROP_PT =
 *  cumulative point-drop floor over that span (default 0). */
export function driftConfig(env = process.env) {
  const rawRuns = env.EVAL_DRIFT_RUNS;
  const runs = rawRuns !== undefined && rawRuns.trim() !== "" ? Number(rawRuns) : NaN;
  const rawDrop = env.EVAL_DRIFT_MIN_DROP_PT;
  const minDropPt = rawDrop !== undefined && rawDrop.trim() !== "" ? Number(rawDrop) : NaN;
  return {
    runs: Number.isInteger(runs) && runs >= 0 ? runs : DEFAULT_DRIFT_RUNS,
    minDropPt: Number.isFinite(minDropPt) && minDropPt >= 0 ? minDropPt : DEFAULT_DRIFT_MIN_DROP_PT,
  };
}

/** Detect per-suite sustained downward drift. For each suite that scored this
 *  run, build its chronological score series (history + this run) and check
 *  whether the last (runs+1) points are strictly decreasing (i.e. `runs`
 *  consecutive drops) and the cumulative drop over that span clears minDropPt.
 *  Returns `[{ suite, runs, fromPct, toPct, dropPt }]` sorted by suite. A
 *  configured `runs` < 2 disables detection (returns []). Pure. */
export function detectDownwardDrift(history = [], currentScores = {}, env = process.env) {
  const { runs: k, minDropPt } = driftConfig(env);
  if (k < 2) return [];
  const hist = Array.isArray(history) ? history : [];
  const out = [];
  for (const [name, score] of Object.entries(currentScores)) {
    if (typeof score !== "number") continue;
    const series = [];
    for (const run of hist) {
      const v = run?.scores?.[name];
      if (typeof v === "number") series.push(v);
    }
    series.push(score);
    if (series.length < k + 1) continue;
    const span = series.slice(-(k + 1));
    let strictlyDown = true;
    for (let i = 1; i < span.length; i++) {
      if (!(span[i] < span[i - 1])) {
        strictlyDown = false;
        break;
      }
    }
    if (!strictlyDown) continue;
    const dropPt = round1((span[0] - span[span.length - 1]) * 100);
    if (dropPt < minDropPt) continue;
    out.push({
      suite: name,
      runs: k,
      fromPct: round1(span[0] * 100),
      toPct: round1(span[span.length - 1] * 100),
      dropPt,
    });
  }
  return out.sort((a, b) => a.suite.localeCompare(b.suite));
}

/** Format a drift record as a single warning line. Pure. */
export function fmtDriftWarning(d) {
  return `downward drift: ${d.suite} fell ${d.runs} run(s) in a row (${d.fromPct.toFixed(1)}% → ${d.toPct.toFixed(1)}%, -${d.dropPt.toFixed(1)}pt)`;
}

/** Append this run's per-suite scores to the rolling history file, trimmed to
 *  the most recent `maxEntries`. Best-effort: a write failure must never change
 *  the job's exit code (the gate owns that), so this only logs on error. Returns
 *  the persisted (trimmed) history. A run that produced no numeric scores (e.g.
 *  a pre-gate execution failure) is not recorded so the trend stays meaningful. */
export function recordRunHistory({
  evalsDir = EVALS_DIR,
  summary,
  maxEntries = DEFAULT_HISTORY_LIMIT,
  now = new Date(),
} = {}) {
  try {
    const scores = extractScores(summary);
    const history = loadHistory(evalsDir);
    if (Object.keys(scores).length === 0) {
      console.log("[eval-notify] run produced no suite scores; not recording history");
      return history;
    }
    history.push({
      ts: now.toISOString(),
      ok: !!summary?.ok,
      outcome: classifyOutcome(summary),
      // Suites that were red this run, so the NEXT passing run can name which
      // ones came back green in its recovery note.
      failed: failingSuites(summary),
      scores,
    });
    const trimmed = history.slice(-Math.max(1, maxEntries));
    const p = join(evalsDir, HISTORY_FILENAME);
    writeFileSync(p, JSON.stringify({ version: HISTORY_VERSION, runs: trimmed }, null, 2) + "\n", "utf8");
    console.log(`[eval-notify] recorded run scores to ${HISTORY_FILENAME} (${trimmed.length} run(s) retained)`);
    return trimmed;
  } catch (err) {
    console.error(`[eval-notify] failed to record score history: ${err?.message ?? err}`);
    return [];
  }
}

/** Parse EVAL_NOTIFY_ON (default "fail"). Unknown values warn + fall back to
 *  fail-only so a typo can never silently widen what gets posted. */
export function parseNotifyOn(env = process.env) {
  const raw = (env.EVAL_NOTIFY_ON ?? "fail").trim().toLowerCase();
  if (raw in NOTIFY_LEVEL) return raw;
  console.warn(`[eval-notify] invalid EVAL_NOTIFY_ON=${env.EVAL_NOTIFY_ON}; defaulting to 'fail'`);
  return "fail";
}

/** Whether an outcome should post under the given trigger level. */
export function shouldNotify(notifyOn, outcome) {
  return OUTCOME_LEVEL[outcome] <= NOTIFY_LEVEL[notifyOn];
}

/** Whether to post a Slack/webhook "recovered" note when a passing run follows a
 *  prior fail. Default on; opt out with EVAL_NOTIFY_RECOVERY=off|false|0|no. This
 *  is the Slack/webhook parallel of the PagerDuty auto-resolve: when a page
 *  clears, on-call gets a one-line explanation on the other channels too. */
export function recoveryNotifyEnabled(env = process.env) {
  const raw = (env.EVAL_NOTIFY_RECOVERY ?? "on").trim().toLowerCase();
  return !["off", "false", "0", "no"].includes(raw);
}

/** Parse a non-negative integer from env, falling back when unset/garbage. */
function intFromEnv(raw, fallback) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

/** Flapping-mute config for recovery notes. When the gate flaps
 *  (fail→pass→fail→pass…) faster than the nightly cadence — e.g. the per-change
 *  gate or a burst of manual re-runs — each pass-after-fail would otherwise emit
 *  its own [RECOVERED] note, spamming on-call. `threshold` recoveries within
 *  `windowMinutes` marks the gate as flapping and suppresses further notes.
 *  Defaults (3 recoveries / 6h) never trip on the 24h nightly cadence, so normal
 *  operation is unchanged; on-call tunes via EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD
 *  / EVAL_NOTIFY_RECOVERY_FLAP_WINDOW_MINUTES, or disables muting entirely with
 *  threshold 0. */
export function recoveryMuteConfig(env = process.env) {
  return {
    threshold: intFromEnv(env.EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD, 3),
    windowMinutes: intFromEnv(env.EVAL_NOTIFY_RECOVERY_FLAP_WINDOW_MINUTES, 360),
  };
}

/** Count recovery transitions (a passing run immediately preceded by a failing
 *  run) in `history` whose passing run falls within `windowMinutes` of `now`.
 *  History is oldest → newest. Pure. */
export function countRecentRecoveries(history, windowMinutes, now = Date.now()) {
  if (!Array.isArray(history) || history.length < 2) return 0;
  const cutoff = now - windowMinutes * 60000;
  let count = 0;
  for (let i = 1; i < history.length; i++) {
    const cur = history[i];
    const prev = history[i - 1];
    const curPassing = !(cur?.outcome === "failed" || cur?.ok === false);
    const prevFailing = prev?.outcome === "failed" || prev?.ok === false;
    if (!curPassing || !prevFailing) continue;
    const ts = new Date(cur?.ts).getTime();
    if (Number.isNaN(ts) || ts < cutoff) continue;
    count++;
  }
  return count;
}

/** Whether the gate is flapping hard enough to mute the recovery note: at least
 *  `threshold` prior recoveries already landed within the window. Muting is
 *  disabled (always false) when threshold is 0. Pure (given `now`). */
export function isRecoveryFlapping(history, env = process.env, now = Date.now()) {
  const { threshold, windowMinutes } = recoveryMuteConfig(env);
  if (threshold <= 0) return false;
  return countRecentRecoveries(history, windowMinutes, now) >= threshold;
}

/** Detect a recovery: a passing run that immediately follows a failed run.
 *  Returns the names (sorted) of suites that were failing in the prior run and
 *  are green now — an empty array still counts as a recovery (the page cleared,
 *  we just couldn't attribute specific suites). Returns null when this is NOT a
 *  recovery: the current run is still failing, there is no prior run, or the
 *  prior run also passed (so there was no page to explain). When the prior run
 *  record predates per-suite failure tracking (`failed` absent), falls back to
 *  naming every suite that is green now. Pure. */
export function detectRecovery(outcome, currentSuites = {}, prevRun = null) {
  if (outcome === "failed") return null;
  if (!prevRun) return null;
  const priorFailed = prevRun.outcome === "failed" || prevRun.ok === false;
  if (!priorFailed) return null;
  const greenNow = (name) => {
    const s = currentSuites[name];
    return !!s && !FAILING_STATUSES.has(s.status);
  };
  const prevFailed = Array.isArray(prevRun.failed) ? prevRun.failed : null;
  if (prevFailed && prevFailed.length > 0) {
    return prevFailed.filter(greenNow).sort();
  }
  return Object.keys(currentSuites).filter(greenNow).sort();
}

/** Timestamp (ISO string) of the FIRST run in the trailing consecutive failing
 *  streak in `history` (the prior runs, oldest → newest, not including the
 *  current run). Walks back from the newest run while runs are failing; returns
 *  the earliest such run's `ts`. Returns null when the most recent prior run was
 *  not failing (no streak to measure) or history is empty. Used to tell on-call
 *  HOW LONG the gate was failing before it recovered. Pure. */
export function failingStreakStart(history) {
  if (!Array.isArray(history) || history.length === 0) return null;
  let startTs = null;
  for (let i = history.length - 1; i >= 0; i--) {
    const r = history[i];
    const failed = r?.outcome === "failed" || r?.ok === false;
    if (!failed) break;
    if (r?.ts) startTs = r.ts;
  }
  return startTs;
}

/** Compact human-readable duration from a millisecond span: "45min", "3h",
 *  "3h 20min", "2d", "2d 5h". Non-finite / non-positive spans render "0min". */
export function fmtDuration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return "0min";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins}min`;
  const hours = Math.floor(mins / 60);
  const remMin = mins % 60;
  if (hours < 24) return remMin > 0 ? `${hours}h ${remMin}min` : `${hours}h`;
  const days = Math.floor(hours / 24);
  const remH = hours % 24;
  return remH > 0 ? `${days}d ${remH}h` : `${days}d`;
}

/** " (was failing for ~3h)" suffix for the recovery note, or "" when the
 *  failing-since timestamp is unknown / unparseable / in the future. Pure. */
function recoveryDurationStr(failingSince, now) {
  if (!failingSince) return "";
  const ts = new Date(failingSince).getTime();
  if (Number.isNaN(ts)) return "";
  const ms = now - ts;
  if (ms <= 0) return "";
  return ` (was failing for ~${fmtDuration(ms)})`;
}

/** Build the concise one-line "recovered" note posted to Slack/webhook when a
 *  passing run follows a prior fail. Names the suites that came back green
 *  (suite names only — no PHI). An empty `recovered` list yields a generic
 *  "all suites" phrasing. When `failingSince` is known, appends how long the
 *  gate had been failing before it recovered. */
export function buildRecoveryText(summary, recovered = [], { failingSince = null, now = Date.now() } = {}) {
  const names = recovered.length > 0 ? recovered.join(", ") : "all suites";
  const tail = classifyOutcome(summary) === "warned" ? " (passing, with non-fatal warnings)" : "";
  const dur = recoveryDurationStr(failingSince, now);
  return `[RECOVERED] eval-gate.nightly_recovered — nightly AI eval gate is GREEN again${tail}; the prior page has cleared${dur}. Back to passing: ${names}`;
}

/** Slack Block Kit body for the recovery note — green bar + one-line headline so
 *  on-call can see at a glance that a previously-failing page has cleared.
 *  Carries only suite names (no PHI), like buildRecoveryText. */
export function buildRecoverySlackMessage(summary, recovered = [], fallback, { failingSince = null, now = Date.now() } = {}) {
  const text = fallback ?? buildRecoveryText(summary, recovered, { failingSince, now });
  const names = recovered.length > 0 ? recovered.join(", ") : "all suites";
  const dur = recoveryDurationStr(failingSince, now).trim();
  const cleared = dur
    ? `the previously-failing page has cleared ${dur}`
    : "the previously-failing page has cleared";
  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `${OUTCOME_EMOJI.clean} RECOVERED — nightly AI eval gate`, emoji: true },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `The nightly AI eval gate is *green again* — ${cleared}.\n*back to passing:* ${names}`,
      },
    },
  ];
  return { text, attachments: [{ color: OUTCOME_COLOR.clean, blocks }] };
}

// notify.mjs sits in the evals/ dir; resolve results relative to this file so
// the notifier works regardless of cwd (the shell entrypoint runs from repo
// root, gate.mjs runs from the package root).
const EVALS_DIR = dirname(fileURLToPath(import.meta.url));

function normalizeSeverity(raw) {
  if (raw === undefined) return "warning";
  return raw in SEVERITY_RANK ? raw : null;
}

/** Parse channel config from env, reusing the env var names + defaults of
 *  src/lib/channels/router.ts. Misconfigured channels are skipped with a
 *  warning (never throw) — same posture as buildChannelsFromEnv. */
export function parseChannels(env = process.env) {
  const channels = [];

  const slackUrl = env.CHANNEL_SLACK_WEBHOOK_URL;
  if (slackUrl) {
    const minSeverity = normalizeSeverity(env.CHANNEL_SLACK_MIN_SEVERITY);
    if (minSeverity === null) {
      console.warn(
        `[eval-notify] invalid CHANNEL_SLACK_MIN_SEVERITY=${env.CHANNEL_SLACK_MIN_SEVERITY}; slack not enabled`,
      );
    } else {
      channels.push({ kind: "slack", url: slackUrl, minSeverity });
    }
  }

  const webhookUrl = env.CHANNEL_WEBHOOK_URL;
  if (webhookUrl) {
    const secret = env.CHANNEL_WEBHOOK_SECRET;
    const hostsRaw = env.CHANNEL_WEBHOOK_ALLOWED_HOSTS;
    const minSeverity = normalizeSeverity(env.CHANNEL_WEBHOOK_MIN_SEVERITY);
    if (!secret || !hostsRaw) {
      console.warn(
        "[eval-notify] CHANNEL_WEBHOOK_URL set without CHANNEL_WEBHOOK_SECRET and CHANNEL_WEBHOOK_ALLOWED_HOSTS; webhook not enabled",
      );
    } else if (secret.length < 16) {
      console.warn("[eval-notify] CHANNEL_WEBHOOK_SECRET must be at least 16 chars; webhook not enabled");
    } else if (minSeverity === null) {
      console.warn(
        `[eval-notify] invalid CHANNEL_WEBHOOK_MIN_SEVERITY=${env.CHANNEL_WEBHOOK_MIN_SEVERITY}; webhook not enabled`,
      );
    } else {
      const allowed = hostsRaw
        .split(",")
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean);
      let host;
      try {
        host = new URL(webhookUrl).host.toLowerCase();
      } catch {
        host = null;
      }
      if (host === null) {
        console.warn(`[eval-notify] CHANNEL_WEBHOOK_URL is not a valid URL; webhook not enabled`);
      } else if (!allowed.includes(host)) {
        console.warn(
          `[eval-notify] webhook host ${host} not in CHANNEL_WEBHOOK_ALLOWED_HOSTS allow-list; webhook not enabled`,
        );
      } else {
        channels.push({ kind: "webhook", url: webhookUrl, secret, minSeverity });
      }
    }
  }

  const pagerdutyKey = env.CHANNEL_PAGERDUTY_ROUTING_KEY;
  if (pagerdutyKey) {
    const minSeverity = normalizeSeverity(env.CHANNEL_PAGERDUTY_MIN_SEVERITY);
    const eventsUrlRaw = env.CHANNEL_PAGERDUTY_EVENTS_URL ?? PAGERDUTY_EVENTS_URL;
    let eventsUrlValid = true;
    try {
      new URL(eventsUrlRaw);
    } catch {
      eventsUrlValid = false;
    }
    if (minSeverity === null) {
      console.warn(
        `[eval-notify] invalid CHANNEL_PAGERDUTY_MIN_SEVERITY=${env.CHANNEL_PAGERDUTY_MIN_SEVERITY}; pagerduty not enabled`,
      );
    } else if (!eventsUrlValid) {
      console.warn(
        `[eval-notify] CHANNEL_PAGERDUTY_EVENTS_URL is not a valid URL; pagerduty not enabled`,
      );
    } else {
      channels.push({
        kind: "pagerduty",
        routingKey: pagerdutyKey,
        eventsUrl: eventsUrlRaw,
        minSeverity,
        // Optional override so a CI run id can pin the incident per attempt;
        // defaults to a single STABLE key (defaultPagerDutyDedupKey) so re-runs
        // fold into one incident AND a passing run on a later night resolves the
        // incident a prior failing night opened.
        dedupKey: env.CHANNEL_PAGERDUTY_DEDUP_KEY,
      });
    }
  }

  return channels;
}

/** Channels whose min-severity threshold accepts `severity`. Mirrors
 *  selectChannels() in src/lib/channels/router.ts. */
export function selectForSeverity(channels, severity = DEFAULT_GATE_SEVERITY) {
  const rank = SEVERITY_RANK[severity];
  return channels.filter((c) => SEVERITY_RANK[c.minSeverity] <= rank);
}

/** Load the gate verdict written by gate.mjs. Falls back to a synthesized
 *  "execution failure" summary (with whatever per-suite results exist) when
 *  the gate did not get far enough to write one — e.g. a live suite crashed
 *  in vitest before gate.mjs ran. */
export function loadSummary(evalsDir = EVALS_DIR) {
  const summaryPath = join(evalsDir, "results", "gate-summary.json");
  if (existsSync(summaryPath)) {
    try {
      return JSON.parse(readFileSync(summaryPath, "utf8"));
    } catch (err) {
      console.warn(`[eval-notify] could not parse gate-summary.json: ${err?.message ?? err}`);
    }
  }
  const resultsDir = join(evalsDir, "results");
  const suites = {};
  if (existsSync(resultsDir)) {
    for (const f of readdirSync(resultsDir)) {
      if (!f.endsWith(".json") || f === "gate-summary.json") continue;
      try {
        const d = JSON.parse(readFileSync(join(resultsDir, f), "utf8"));
        if (typeof d.suite === "string" && typeof d.score === "number") {
          suites[d.suite] = { score: d.score, status: "ran" };
        }
      } catch {
        // ignore unparseable result file
      }
    }
  }
  return {
    ok: false,
    executionFailure: true,
    failures: ["eval run failed before the regression gate (live-suite execution failure)"],
    warnings: [],
    suites,
    floor: { active: false, value: null },
  };
}

function fmtPct(n) {
  return typeof n === "number" ? `${(n * 100).toFixed(1)}%` : "n/a";
}

/** Build the concise human-readable alert body. Scores + suite names +
 *  which check tripped — never any content beyond gate-derived literals.
 *  The header + severity reflect the run outcome (failed | warned | clean). */
export function buildSummaryText(summary, { exitCode, outcome, severity, trends, sparks } = {}) {
  const o = outcome ?? classifyOutcome(summary);
  const sev = severity ?? SEVERITY_BY_OUTCOME[o];
  const lines = [];
  lines.push(`[ALERT ${sev}] ${OUTCOME_HEADER[o]}`);
  if (summary.executionFailure) {
    lines.push("cause: live-suite execution failure (eval run exited before the regression gate)");
  }
  for (const f of summary.failures ?? []) lines.push(`  FAIL ${f}`);
  for (const w of summary.warnings ?? []) lines.push(`  WARN ${w}`);

  const suites = summary.suites ?? {};
  const names = Object.keys(suites).sort();
  if (names.length > 0) {
    lines.push("suite scores (vs previous run):");
    for (const name of names) {
      const s = suites[name];
      let extra = "";
      if (s.baseline != null) extra = ` (baseline ${fmtPct(s.baseline)})`;
      else if (s.floor != null) extra = ` (floor ${fmtPct(s.floor)})`;
      lines.push(`  ${name}: ${fmtPct(s.score)}${extra}${fmtTrend(trends?.[name])}${fmtSparkline(sparks?.[name])} [${s.status ?? "?"}]`);
    }
  }
  if (summary.floor?.active) {
    lines.push(`live-suite floor: EVAL_LLM_MIN_SCORE=${summary.floor.value}`);
  }
  if (exitCode !== undefined) lines.push(`gate exit code: ${exitCode}`);
  return lines.join("\n");
}

/** Build a Slack Block Kit message body for the run outcome. The colored
 *  attachment bar + one-word headline (PASSED / WARNINGS / FAILED) let on-call
 *  triage the daily heads-up at a glance; the dense per-suite scores are tucked
 *  into a code block so they stay scannable. `text` is kept as the notification
 *  fallback (and what shows in push notifications). Like buildSummaryText, the
 *  body carries only gate-derived literals (scores + suite names) — no PHI. */
export function buildSlackMessage(summary, { exitCode, outcome, severity, trends, sparks } = {}) {
  const o = outcome ?? classifyOutcome(summary);
  const sev = severity ?? SEVERITY_BY_OUTCOME[o];
  const fallback = buildSummaryText(summary, { exitCode, outcome: o, severity: sev, trends, sparks });

  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `${OUTCOME_EMOJI[o]} ${OUTCOME_HEADLINE[o]} — nightly AI eval gate`, emoji: true },
    },
  ];

  const failCount = (summary.failures ?? []).length;
  const warnCount = (summary.warnings ?? []).length;
  const suiteCount = Object.keys(summary.suites ?? {}).length;
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `*severity:* ${sev}  •  *suites:* ${suiteCount}  •  *failures:* ${failCount}  •  *warnings:* ${warnCount}`,
      },
    ],
  });

  if (summary.executionFailure) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: ":warning: *cause:* live-suite execution failure (eval run exited before the regression gate)",
      },
    });
  }

  const detailLines = [];
  for (const f of summary.failures ?? []) detailLines.push(`FAIL  ${f}`);
  for (const w of summary.warnings ?? []) detailLines.push(`WARN  ${w}`);
  if (detailLines.length > 0) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: "```" + detailLines.join("\n") + "```" },
    });
  }

  const suites = summary.suites ?? {};
  const names = Object.keys(suites).sort();
  if (names.length > 0) {
    const scoreLines = names.map((name) => {
      const s = suites[name];
      let extra = "";
      if (s.baseline != null) extra = ` (baseline ${fmtPct(s.baseline)})`;
      else if (s.floor != null) extra = ` (floor ${fmtPct(s.floor)})`;
      return `${name}: ${fmtPct(s.score)}${extra}${fmtTrend(trends?.[name])}${fmtSparkline(sparks?.[name])} [${s.status ?? "?"}]`;
    });
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: "*suite scores* (▲▼▬ vs previous run · sparkline = last runs)\n```" + scoreLines.join("\n") + "```" },
    });
  }

  const footerBits = [];
  if (summary.floor?.active) footerBits.push(`live-suite floor: EVAL_LLM_MIN_SCORE=${summary.floor.value}`);
  if (exitCode !== undefined) footerBits.push(`gate exit code: ${exitCode}`);
  if (footerBits.length > 0) {
    blocks.push({
      type: "context",
      elements: [{ type: "mrkdwn", text: footerBits.join("  •  ") }],
    });
  }

  return {
    text: fallback,
    attachments: [{ color: OUTCOME_COLOR[o], blocks }],
  };
}

/** HMAC-SHA256 over `${timestampSec}.${body}`. MUST stay byte-for-byte
 *  identical to signWebhookBody() in src/lib/channels/adapters/webhook.ts —
 *  receivers verify against that exact scheme. Locked by a cross-check unit
 *  test (eval-gate-notify.test.ts). */
export function signWebhookBody(secret, timestampSec, body) {
  return createHmac("sha256", secret).update(`${timestampSec}.${body}`).digest("hex");
}

/** Default dedup key when CHANNEL_PAGERDUTY_DEDUP_KEY is unset: a single STABLE
 *  key (no date) shared by every nightly run.
 *
 *  Why stable instead of per-UTC-day: PagerDuty folds a `trigger` into the open
 *  incident with the same dedup_key, and a `resolve` clears exactly that key.
 *  A per-day key (`eval-gate-nightly/<date>`) meant a fail on night N and a
 *  pass on night N+1 used DIFFERENT keys, so the recovery resolve never cleared
 *  the prior day's page unless operators pinned CHANNEL_PAGERDUTY_DEDUP_KEY by
 *  hand. With one stable key, cross-night recovery works out of the box.
 *
 *  Trade-offs this preserves:
 *   - Same-night re-runs still fold into one incident (same key while open).
 *   - A pass on any later night resolves the still-open incident from an
 *     earlier failing night (same key).
 *   - Consecutive failing nights fold into the one open incident rather than
 *     paging once per night — acceptable because it is the same unresolved
 *     failure; PagerDuty re-opens a fresh incident on the next trigger only
 *     after the prior one is resolved (manually or by a passing run).
 *  Operators who DO want a distinct incident per attempt (e.g. one per CI run)
 *  set CHANNEL_PAGERDUTY_DEDUP_KEY explicitly, which always wins. */
export function defaultPagerDutyDedupKey() {
  return "eval-gate-nightly";
}

/** Default dedup key for the heartbeat / dead-man's-switch page when
 *  CHANNEL_PAGERDUTY_DEDUP_KEY is unset: a single STABLE key (no date).
 *
 *  Why stable instead of per-UTC-day: the heartbeat checker pages a `trigger`
 *  when the nightly mechanism goes quiet and must clear it with a `resolve`
 *  once it comes back. A per-day key (`eval-gate-heartbeat/<date>`) meant the
 *  staleness trigger and the recovery resolve could land on DIFFERENT keys
 *  whenever the outage straddled a UTC midnight, so the resolve never cleared
 *  the open "went quiet" incident. With one stable key the recovery resolve
 *  targets exactly the incident the staleness trigger opened — the same
 *  reasoning as defaultPagerDutyDedupKey() for the run notifier.
 *
 *  Kept distinct from defaultPagerDutyDedupKey() so a heartbeat (liveness) page
 *  and an eval-gate run (quality) page are separate incidents — a quiet job and
 *  a failing suite are different problems on-call must see independently. */
export function defaultHeartbeatDedupKey() {
  return "eval-gate-heartbeat";
}

/** Default dedup key for the nightly Temporal live-cluster integration gate page
 *  when CHANNEL_PAGERDUTY_DEDUP_KEY is unset: a single STABLE key (no date), for
 *  the same reason as the other two defaults — re-runs fold into one incident.
 *
 *  Kept DISTINCT from both defaultPagerDutyDedupKey() (the eval-gate run) and
 *  defaultHeartbeatDedupKey() (the dead-man's switch) so a failing Temporal gate
 *  is its own incident: a broken durable-orchestration backend is a different
 *  problem from a failing detector/agent quality suite or a quiet nightly job,
 *  and on-call must see them independently. */
export function defaultTemporalDedupKey() {
  return "temporal-integration-nightly";
}

/** Send a PagerDuty Events API v2 `resolve` to clear an open heartbeat "went
 *  quiet" incident. Keyed on the SAME dedup_key the staleness trigger uses
 *  (`channel.dedupKey || defaultHeartbeatDedupKey()`), so a healthy check
 *  resolves exactly the incident a prior stale check raised. A resolve needs
 *  only the routing key + dedup_key + action (no payload); resolving a key with
 *  no open incident is a harmless no-op, so it is safe to fire on every healthy
 *  check. `redirect: "error"` blocks redirect-based SSRF. */
async function sendHeartbeatPagerDutyResolve(channel, fetchImpl) {
  const dedupKey = channel.dedupKey || defaultHeartbeatDedupKey();
  const event = {
    routing_key: channel.routingKey,
    event_action: "resolve",
    dedup_key: dedupKey,
  };
  const res = await fetchImpl(channel.eventsUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(event),
    redirect: "error",
  });
  return { channel: "pagerduty", ok: !!res.ok, statusCode: res.status, dedupKey, action: "resolve" };
}

/** Clear any open heartbeat "went quiet" page when a `--check` finds the nightly
 *  mechanism is alive again (heartbeat fresh). Iterates the configured PagerDuty
 *  channels and sends a `resolve` keyed on the SAME stable dedup_key the stale
 *  trigger uses, so liveness recovery folds/clears the prior incident
 *  automatically — the heartbeat parallel of the run notifier's auto-resolve.
 *
 *  Intentionally NOT subject to the per-channel severity gate: a resolve carries
 *  no severity, and gating it would only leave a stale page lingering. Slack and
 *  generic webhooks have no resolve concept, so only PagerDuty gets the signal.
 *  Inert (empty `sent`) when nothing is configured. Never throws — each send
 *  error is captured per-channel so the checker's exit code is unaffected. */
export async function resolveHeartbeat({ env = process.env, fetchImpl = fetch } = {}) {
  const channels = parseChannels(env);
  const sent = [];
  for (const channel of channels) {
    if (channel.kind !== "pagerduty") continue;
    try {
      const result = await sendHeartbeatPagerDutyResolve(channel, fetchImpl);
      sent.push(result);
      console.log(
        `[eval-notify] pagerduty: heartbeat resolve ${result.ok ? "ok" : "FAILED"} (status ${result.statusCode ?? "n/a"}, dedup_key ${result.dedupKey})`,
      );
    } catch (err) {
      sent.push({ channel: "pagerduty", ok: false, action: "resolve", err: err?.message ?? String(err) });
      console.error(`[eval-notify] pagerduty: heartbeat resolve error: ${err?.message ?? err}`);
    }
  }
  return { sent };
}

/** Send a PagerDuty Events API v2 `resolve` to clear an open nightly-Temporal-
 *  gate incident. Keyed on the SAME stable dedup_key the Temporal trigger path
 *  uses (defaultTemporalDedupKey — note the trigger passes this explicitly,
 *  NOT channel.dedupKey, so the resolve must too, or a recovering run would fail
 *  to clear the page it raised). A resolve needs only routing key + dedup_key +
 *  action; resolving a key with no open incident is a harmless no-op.
 *  `redirect: "error"` blocks redirect-based SSRF. */
async function sendTemporalPagerDutyResolve(channel, fetchImpl) {
  const dedupKey = defaultTemporalDedupKey();
  const event = {
    routing_key: channel.routingKey,
    event_action: "resolve",
    dedup_key: dedupKey,
  };
  const res = await fetchImpl(channel.eventsUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(event),
    redirect: "error",
  });
  return { channel: "pagerduty", ok: !!res.ok, statusCode: res.status, dedupKey, action: "resolve" };
}

/** #90: clear any open nightly-Temporal-gate page when the live-cluster gate
 *  recovers (a passing run). Iterates the configured PagerDuty channels and
 *  sends a `resolve` on the stable Temporal dedup key — the Temporal parallel of
 *  the eval-gate run notifier's auto-resolve. Intentionally NOT subject to the
 *  per-channel severity gate (a resolve carries no severity; gating it would
 *  only leave a stale page lingering). Slack and generic webhooks have no resolve
 *  concept, so only PagerDuty gets the signal. Inert (empty `sent`) when nothing
 *  is configured. Never throws — each send error is captured per-channel so the
 *  job's exit code is unaffected. */
export async function resolveTemporalGate({ env = process.env, fetchImpl = fetch } = {}) {
  const channels = parseChannels(env);
  const sent = [];
  for (const channel of channels) {
    if (channel.kind !== "pagerduty") continue;
    try {
      const result = await sendTemporalPagerDutyResolve(channel, fetchImpl);
      sent.push(result);
      console.log(
        `[temporal-notify] pagerduty: temporal resolve ${result.ok ? "ok" : "FAILED"} (status ${result.statusCode ?? "n/a"}, dedup_key ${result.dedupKey})`,
      );
    } catch (err) {
      sent.push({ channel: "pagerduty", ok: false, action: "resolve", err: err?.message ?? String(err) });
      console.error(`[temporal-notify] pagerduty: temporal resolve error: ${err?.message ?? err}`);
    }
  }
  return { sent };
}

/** Send a PagerDuty Events API v2 `resolve` to clear the incident a matching
 *  failing run would have opened. Keyed on the SAME dedup_key the trigger path
 *  computes (`channel.dedupKey || defaultPagerDutyDedupKey()`), so a passing
 *  run resolves exactly the incident its failing counterpart raised. A resolve
 *  needs only the routing key + dedup_key + action (no payload). Resolving a
 *  dedup_key with no open incident is a harmless no-op on PagerDuty's side, so
 *  this is safe to fire on every passing run. `redirect: "error"` blocks
 *  redirect-based SSRF on the operator-configured endpoint. */
async function sendPagerDutyResolve(channel, fetchImpl) {
  const dedupKey = channel.dedupKey || defaultPagerDutyDedupKey();
  const event = {
    routing_key: channel.routingKey,
    event_action: "resolve",
    dedup_key: dedupKey,
  };
  const res = await fetchImpl(channel.eventsUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(event),
    redirect: "error",
  });
  return { channel: "pagerduty", ok: !!res.ok, statusCode: res.status, dedupKey, action: "resolve" };
}

/** Post a concise "recovered" note to a Slack or generic-webhook channel (never
 *  PagerDuty — that channel gets the auto-resolve instead). Slack receives a
 *  green-bar Block Kit message; the webhook receives an HMAC-signed payload using
 *  the SAME signing scheme as the app's webhook adapter. `redirect: "error"`
 *  blocks redirect-based SSRF. Body carries suite names only — no PHI. */
async function sendRecoveryNote(channel, text, summary, recovered, fetchImpl, { failingSince = null, now = Date.now() } = {}) {
  if (channel.kind === "slack") {
    const message = buildRecoverySlackMessage(summary, recovered, text, { failingSince, now });
    const res = await fetchImpl(channel.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(message),
    });
    return { channel: "slack", ok: !!res.ok, statusCode: res.status, action: "recovery" };
  }

  const payload = {
    kind: RECOVERY_KIND,
    severity: "warning",
    outcome: classifyOutcome(summary),
    ok: !!summary.ok,
    recovered,
    summary: text,
    suites: summary.suites ?? {},
    occurredAt: new Date().toISOString(),
  };
  const body = JSON.stringify(payload);
  const timestampSec = Math.floor(Date.now() / 1000);
  const sig = signWebhookBody(channel.secret, timestampSec, body);
  const res = await fetchImpl(channel.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-phi-audit-signature": `sha256=${sig}`,
      "x-phi-audit-timestamp": String(timestampSec),
    },
    body,
    redirect: "error",
  });
  return { channel: "webhook", ok: !!res.ok, statusCode: res.status, action: "recovery" };
}

async function sendToChannel(channel, text, summary, fetchImpl, { outcome, severity, exitCode, trends, sparks }) {
  if (channel.kind === "slack") {
    const message = buildSlackMessage(summary, { exitCode, outcome, severity, trends, sparks });
    const res = await fetchImpl(channel.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(message),
    });
    return { channel: "slack", ok: !!res.ok, statusCode: res.status };
  }

  if (channel.kind === "pagerduty") {
    // Events API v2 `trigger`. The routing key is the secret; no HMAC /
    // host allow-list needed (cf. Slack). `redirect: "error"` blocks
    // redirect-based SSRF on the operator-configured endpoint. Body carries
    // suite scores + names only (synthetic fixtures → no PHI by construction).
    const dedupKey = channel.dedupKey || defaultPagerDutyDedupKey();
    const event = {
      routing_key: channel.routingKey,
      event_action: "trigger",
      dedup_key: dedupKey,
      payload: {
        // PagerDuty caps `summary` at 1024 chars.
        summary: text.slice(0, 1024),
        source: "phi-audit eval-gate.nightly",
        severity: PAGERDUTY_SEVERITY[severity] ?? "error",
        timestamp: new Date().toISOString(),
        component: "eval-gate",
        group: "phi-audit",
        class: OUTCOME_KIND[outcome],
        custom_details: {
          ok: !!summary.ok,
          outcome,
          suites: summary.suites ?? {},
          failures: summary.failures ?? [],
          warnings: summary.warnings ?? [],
          floor: summary.floor ?? { active: false, value: null },
        },
      },
    };
    const res = await fetchImpl(channel.eventsUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
      redirect: "error",
    });
    return { channel: "pagerduty", ok: !!res.ok, statusCode: res.status, dedupKey, action: "trigger" };
  }

  // Generic webhook: signed JSON body, same signature scheme as the app's
  // webhook adapter. `redirect: "error"` blocks redirect-based SSRF.
  const payload = {
    kind: OUTCOME_KIND[outcome],
    severity,
    outcome,
    ok: !!summary.ok,
    summary: text,
    suites: summary.suites ?? {},
    trends: trends ?? {},
    failures: summary.failures ?? [],
    warnings: summary.warnings ?? [],
    floor: summary.floor ?? { active: false, value: null },
    occurredAt: new Date().toISOString(),
  };
  const body = JSON.stringify(payload);
  const timestampSec = Math.floor(Date.now() / 1000);
  const sig = signWebhookBody(channel.secret, timestampSec, body);
  const res = await fetchImpl(channel.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-phi-audit-signature": `sha256=${sig}`,
      "x-phi-audit-timestamp": String(timestampSec),
    },
    body,
    redirect: "error",
  });
  return { channel: "webhook", ok: !!res.ok, statusCode: res.status };
}

/** Post a prebuilt alert to every configured + severity-eligible channel.
 *  Slack receives the human-readable `text`; the generic webhook receives the
 *  HMAC-signed `payload` (same signing scheme as the app's webhook adapter,
 *  `redirect: "error"` blocks redirect-based SSRF). Inert (`{ skipped: true }`)
 *  when nothing is configured or no channel accepts `severity`. Never throws —
 *  each send error is captured per-channel. Shared by the eval-gate run
 *  notifier (notifyEvalGate) AND the heartbeat / dead-man's-switch checker
 *  (heartbeat.mjs) so both land in the SAME place via the SAME CHANNEL_*
 *  config + severity gating. */
export async function postToChannels({
  env = process.env,
  severity,
  text,
  payload,
  fetchImpl = fetch,
  pagerDutyDedupKey = defaultHeartbeatDedupKey(),
  pagerDutySource = "phi-audit eval-gate.heartbeat",
}) {
  const channels = parseChannels(env);
  if (channels.length === 0) {
    console.log(
      "[eval-notify] no channel configured (CHANNEL_SLACK_WEBHOOK_URL / CHANNEL_WEBHOOK_URL); skipping alert",
    );
    return { skipped: true, sent: [] };
  }
  const selected = selectForSeverity(channels, severity);
  if (selected.length === 0) {
    console.log(
      `[eval-notify] ${channels.length} channel(s) configured but none accept '${severity}' severity; skipping`,
    );
    return { skipped: true, sent: [] };
  }

  const sent = [];
  for (const channel of selected) {
    try {
      let result;
      if (channel.kind === "slack") {
        const res = await fetchImpl(channel.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text }),
        });
        result = { channel: "slack", ok: !!res.ok, statusCode: res.status };
      } else if (channel.kind === "pagerduty") {
        // PagerDuty Events API v2 trigger. Routing key is the secret; no HMAC /
        // host allow-list needed (cf. webhook). Liveness metadata only — no PHI.
        // A single STABLE dedup_key (no date) so a still-stale check folds into
        // the one open "went quiet" incident AND the resolve a later healthy
        // check sends (resolveHeartbeat) targets exactly this incident.
        const dedupKey = channel.dedupKey || pagerDutyDedupKey;
        const event = {
          routing_key: channel.routingKey,
          event_action: "trigger",
          dedup_key: dedupKey,
          payload: {
            summary: String(text).slice(0, 1024),
            source: pagerDutySource,
            severity: PAGERDUTY_SEVERITY[severity] ?? "error",
            timestamp: new Date().toISOString(),
            component: "eval-gate",
            group: "phi-audit",
            class: payload?.kind ?? "eval_gate_alert",
            custom_details: payload,
          },
        };
        const res = await fetchImpl(channel.eventsUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(event),
          redirect: "error",
        });
        result = { channel: "pagerduty", ok: !!res.ok, statusCode: res.status, dedupKey };
      } else {
        // Generic webhook: signed JSON body, same signature scheme as the
        // app's webhook adapter. `redirect: "error"` blocks redirect SSRF.
        const body = JSON.stringify(payload);
        const timestampSec = Math.floor(Date.now() / 1000);
        const sig = signWebhookBody(channel.secret, timestampSec, body);
        const res = await fetchImpl(channel.url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-phi-audit-signature": `sha256=${sig}`,
            "x-phi-audit-timestamp": String(timestampSec),
          },
          body,
          redirect: "error",
        });
        result = { channel: "webhook", ok: !!res.ok, statusCode: res.status };
      }
      sent.push(result);
      console.log(
        `[eval-notify] ${result.channel}: ${result.ok ? "ok" : "FAILED"} (status ${result.statusCode ?? "n/a"})`,
      );
    } catch (err) {
      sent.push({ channel: channel.kind, ok: false, err: err?.message ?? String(err) });
      console.error(`[eval-notify] ${channel.kind}: send error: ${err?.message ?? err}`);
    }
  }
  return { skipped: false, sent };
}

/** Post the eval-gate run summary to every configured + severity-eligible
 *  channel, subject to the EVAL_NOTIFY_ON trigger level. Inert (returns
 *  `{ skipped: true }`) when the outcome is below the trigger level, nothing is
 *  configured, or no channel accepts the outcome's severity. Never throws — a
 *  notification failure must not change the job's exit code, which the shell
 *  entrypoint owns. */
export async function notifyEvalGate({
  env = process.env,
  evalsDir = EVALS_DIR,
  summary,
  history,
  fetchImpl = fetch,
  exitCode,
  now = Date.now(),
} = {}) {
  const baseVerdict = summary ?? loadSummary(evalsDir);
  const notifyOn = parseNotifyOn(env);
  // Trend vs. the previous nightly run, read from the rolling history (read-only
  // here — the run is appended separately after dispatch so the comparison is
  // always against prior runs, never against itself).
  const runs = history ?? loadHistory(evalsDir);
  // #24 multi-night downward-drift: a sustained slide that stays inside the
  // per-run regression tolerance never trips the gate, so surface it as a
  // (non-fatal) warning. Merge it into a dispatch-only copy of the verdict so the
  // run *history* still records the raw gate outcome (drift is a notify-time
  // signal, not a gate verdict) — but the dispatched alert is promoted to
  // "warned" so on-call actually hears about the erosion under the default
  // fail-only trigger.
  const drift = detectDownwardDrift(runs, extractScores(baseVerdict), env);
  const verdict =
    drift.length > 0
      ? { ...baseVerdict, warnings: [...(baseVerdict.warnings ?? []), ...drift.map(fmtDriftWarning)] }
      : baseVerdict;
  const outcome = classifyOutcome(verdict);
  const severity = SEVERITY_BY_OUTCOME[outcome];
  const trends = computeTrends(verdict.suites ?? {}, previousScores(runs));
  // #23 per-suite sparkline of the last N runs + this run.
  const sparks = computeSparklines(runs, verdict.suites ?? {});
  const isPassing = outcome !== "failed";

  const channels = parseChannels(env);
  const sent = [];

  // PagerDuty auto-resolve (recovery signal). On any passing run, clear the
  // incident a matching failing run would have opened — keyed on the SAME
  // dedup_key the trigger path uses. This is intentionally NOT subject to
  // EVAL_NOTIFY_ON or the per-channel severity gate: the default trigger level
  // is fail-only (a passing run otherwise posts nothing), yet on-call still
  // wants a previously-opened page to clear on recovery. A resolve for a
  // non-existent incident is a harmless no-op, and it carries no severity, so
  // gating it would only leave stale pages lingering. Slack/webhook have no
  // resolve concept and are untouched here; only PagerDuty gets the signal.
  if (isPassing) {
    for (const channel of channels) {
      if (channel.kind !== "pagerduty") continue;
      try {
        const result = await sendPagerDutyResolve(channel, fetchImpl);
        sent.push(result);
        console.log(
          `[eval-notify] pagerduty: resolve ${result.ok ? "ok" : "FAILED"} (status ${result.statusCode ?? "n/a"}, dedup_key ${result.dedupKey})`,
        );
      } catch (err) {
        sent.push({ channel: "pagerduty", ok: false, action: "resolve", err: err?.message ?? String(err) });
        console.error(`[eval-notify] pagerduty: resolve error: ${err?.message ?? err}`);
      }
    }
  }

  const willPostSummary = shouldNotify(notifyOn, outcome);

  // Recovery note (Slack/webhook parallel of the PagerDuty auto-resolve above).
  // When a passing run follows a prior fail, the page just cleared silently — so
  // post a concise one-line "recovered" note naming the suites that came back
  // green, so the vanished page is explained rather than mysterious. It fires
  // only when the normal run summary would NOT otherwise post (the default
  // fail-only trigger), so a recovery night never produces BOTH a recovery note
  // AND a full confirmation. Honors the per-channel min-severity gate (warning
  // class) and the EVAL_NOTIFY_RECOVERY opt-out. Never PagerDuty (it got the
  // resolve). Routine consecutive green nights never trigger it — there was no
  // prior fail to recover from.
  if (isPassing && !willPostSummary && recoveryNotifyEnabled(env)) {
    const recovered = detectRecovery(outcome, verdict.suites ?? {}, previousRun(runs));
    if (recovered !== null && isRecoveryFlapping(runs, env, now)) {
      // Flapping mute: the gate has bounced fail→pass repeatedly within the
      // window, so on-call already knows it is unstable. Suppress the repeated
      // [RECOVERED] note (PagerDuty still got its resolve above) to avoid spam.
      const { threshold, windowMinutes } = recoveryMuteConfig(env);
      console.log(
        `[eval-notify] muting recovery note: gate is flapping (>=${threshold} recoveries in last ${windowMinutes}min); set EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD=0 to disable muting`,
      );
    } else if (recovered !== null) {
      const eligible = selectForSeverity(channels, "warning").filter((c) => c.kind !== "pagerduty");
      if (eligible.length > 0) {
        const failingSince = failingStreakStart(runs);
        const recoveryText = buildRecoveryText(verdict, recovered, { failingSince, now });
        for (const channel of eligible) {
          try {
            const result = await sendRecoveryNote(channel, recoveryText, verdict, recovered, fetchImpl, { failingSince, now });
            sent.push(result);
            console.log(
              `[eval-notify] ${result.channel}: recovery note ${result.ok ? "ok" : "FAILED"} (status ${result.statusCode ?? "n/a"})`,
            );
          } catch (err) {
            sent.push({ channel: channel.kind, ok: false, action: "recovery", err: err?.message ?? String(err) });
            console.error(`[eval-notify] ${channel.kind}: recovery note error: ${err?.message ?? err}`);
          }
        }
      }
    }
  }

  if (!willPostSummary) {
    console.log(
      `[eval-notify] run outcome '${outcome}' is below EVAL_NOTIFY_ON='${notifyOn}'; not posting`,
    );
    return { skipped: sent.length === 0, sent, outcome, severity };
  }

  if (channels.length === 0) {
    console.log(
      "[eval-notify] no channel configured (CHANNEL_SLACK_WEBHOOK_URL / CHANNEL_WEBHOOK_URL / CHANNEL_PAGERDUTY_ROUTING_KEY); skipping alert",
    );
    return { skipped: sent.length === 0, sent, outcome, severity };
  }
  const selected = selectForSeverity(channels, severity);
  // On a passing run, PagerDuty has already been handled via the auto-resolve
  // above; never also send it a (warning-severity) `trigger` for a green run —
  // that would open the very incident we just cleared.
  const notifyChannels = isPassing ? selected.filter((c) => c.kind !== "pagerduty") : selected;
  if (notifyChannels.length === 0) {
    console.log(
      `[eval-notify] ${channels.length} channel(s) configured but none accept '${severity}' severity; skipping`,
    );
    return { skipped: sent.length === 0, sent, outcome, severity };
  }

  const text = buildSummaryText(verdict, { exitCode, outcome, severity, trends, sparks });
  for (const channel of notifyChannels) {
    try {
      const result = await sendToChannel(channel, text, verdict, fetchImpl, { outcome, severity, exitCode, trends, sparks });
      sent.push(result);
      console.log(
        `[eval-notify] ${result.channel}: ${result.ok ? "ok" : "FAILED"} (status ${result.statusCode ?? "n/a"})`,
      );
    } catch (err) {
      sent.push({ channel: channel.kind, ok: false, err: err?.message ?? String(err) });
      console.error(`[eval-notify] ${channel.kind}: send error: ${err?.message ?? err}`);
    }
  }
  return { skipped: false, sent, outcome, severity };
}

// CLI entrypoint: invoked by deploy/scripts/eval-gate-llm.sh after every run
// (pass or fail). The EVAL_NOTIFY_ON trigger level decides whether a given
// outcome actually posts.
const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const exitArg = process.argv.find((a) => a.startsWith("--exit-code="));
  const exitCode = exitArg ? Number(exitArg.split("=")[1]) : undefined;
  // Load the verdict once so the dispatch and the history append agree on what
  // ran. Dispatch first (it reads the PRIOR history to compute the trend), then
  // append this run so the next nightly run can trend against it.
  const verdict = loadSummary();
  notifyEvalGate({ summary: verdict, exitCode })
    .catch((err) => {
      console.error(`[eval-notify] fatal: ${err?.message ?? err}`);
    })
    .finally(() => {
      recordRunHistory({ summary: verdict, maxEntries: historyLimit() });
      // Always exit 0: the gate's own exit code (preserved by the shell
      // wrapper) is the source of truth for the job result.
      process.exitCode = 0;
    });
}
