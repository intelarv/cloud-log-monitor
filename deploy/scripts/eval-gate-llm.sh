#!/usr/bin/env bash
# Nightly / manual eval job for the credentialed suites. Runs the full eval
# suite WITH EVAL_LLM=1, which additionally executes the two non-deterministic,
# credential-backed suites (citation-live, agent-agreement) on top of the six
# deterministic ones. These need a real DATABASE_URL and a configured LLM
# runtime, so this job is intended for environments where those secrets exist
# (a nightly/manual CI job), not the per-change gate (deploy/scripts/eval-gate.sh).
#
# The regression gate (evals/gate.mjs) only ever compares the deterministic
# suites against evals/baseline.json; the two LLM suites are reported as
# warnings and never baselined (see evals/gate.mjs NON_DETERMINISTIC).

set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "eval-gate-llm: DATABASE_URL is not set — the live suites need a real database." >&2
  echo "eval-gate-llm: run this only where credentials are available (nightly/manual job)." >&2
  exit 1
fi

export EVAL_LLM=1

# Hard-fail policy for the nightly job (see evals/gate.mjs):
#   - Deterministic suite regressions > tolerance ALWAYS hard-fail.
#   - A live LLM/DB suite that crashes or emits no result ALWAYS hard-fails
#     (vitest exits non-zero before the gate runs).
#   - Live-suite *score* regressions are surfaced as warnings by default
#     (these suites are non-deterministic, so delta-based paging is flaky).
# EVAL_LLM_MIN_SCORE turns the live-suite scores into a hard gate: any
# non-deterministic suite scoring below this absolute floor (0..1) fails the
# run. Leave unset to keep the live scores as warnings only; set e.g.
# EVAL_LLM_MIN_SCORE=0.5 to page on catastrophic live-agent regressions
# without flaky run-to-run noise. Inherited by gate.mjs from the environment.
if [[ -n "${EVAL_LLM_MIN_SCORE:-}" ]]; then
  echo "eval-gate-llm: live-suite hard-fail floor active (EVAL_LLM_MIN_SCORE=${EVAL_LLM_MIN_SCORE})"
else
  echo "eval-gate-llm: live-suite scores reported as warnings (set EVAL_LLM_MIN_SCORE to hard-fail on a floor)"
fi

# Which run outcomes post to the configured channel(s). The notifier classifies
# each run as failed | warned | clean and only posts when the outcome meets this
# trigger level (failed=fail, warned=warn, clean=always):
#   fail   (default) — only a hard-fail posts (prior behavior).
#   warn            — also post passing-with-warnings runs.
#   always          — also post an all-green confirmation, so silence is never
#                     ambiguous to on-call.
echo "eval-gate-llm: channel notify trigger EVAL_NOTIFY_ON=${EVAL_NOTIFY_ON:-fail}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Signal the external uptime monitor that a nightly run is BEGINNING, before the
# eval suite executes. With a start signal recorded, the monitor can alert fast
# when the matching completion never arrives — a hung suite or an LLM call wedged
# past its timeout — instead of waiting out the whole grace window, and can tell
# "started but hung" from "never scheduled". Inert when HEARTBEAT_PING_URL is
# unset; best-effort and non-fatal so it never blocks or fails the eval run.
echo "eval-gate-llm: signalling external heartbeat start"
node "$ROOT/artifacts/api-server/evals/heartbeat.mjs" --start \
  || echo "eval-gate-llm: heartbeat start errored (non-fatal); see logs above" >&2

echo "eval-gate-llm: running full eval suite (EVAL_LLM=1) + regression gate"
# Run the gate without -e tripping so we can alert on failure and still
# preserve the gate's exit code as the job result.
set +e
pnpm --filter @workspace/api-server run eval
gate_status=$?
set -e

if [[ $gate_status -eq 0 ]]; then
  echo "eval-gate-llm: OK"
else
  echo "eval-gate-llm: gate FAILED (exit ${gate_status})" >&2
fi

# Dispatch the run summary (suite scores + which check tripped) to any configured
# channel (Slack / webhook), reusing the same CHANNEL_* config + severity gating
# as the application's finding alerts. The notifier reads the gate verdict and
# only posts when the run outcome (failed | warned | clean) meets the
# EVAL_NOTIFY_ON trigger level — so a hard-fail always posts (default fail-only),
# while warn/always additionally surface warning + all-green runs at "warning"
# severity. Inert when no channel is set or the outcome is below the trigger.
#
# PagerDuty additionally gets a recovery signal: on any PASSING run the notifier
# sends an Events API v2 `resolve` keyed on the SAME dedup_key a failing run
# would use, auto-closing the incident a prior hard-fail opened. That resolve is
# gated only by CHANNEL_PAGERDUTY_ROUTING_KEY (not EVAL_NOTIFY_ON / severity), so
# stale pages clear even under the default fail-only trigger. Slack/webhook have
# no resolve concept and instead get a one-line [RECOVERED] note (naming the
# suites that came back green) when a pass follows a prior fail — gated by
# EVAL_NOTIFY_RECOVERY (default on) and only when the normal summary would not
# otherwise post, so there are no duplicate or routine-green posts.
#
# The notifier never throws and never changes the job result — the gate's exit
# code below is the source of truth.
echo "eval-gate-llm: dispatching run summary to configured channels (EVAL_NOTIFY_ON=${EVAL_NOTIFY_ON:-fail})"
node "$ROOT/artifacts/api-server/evals/notify.mjs" --exit-code="$gate_status" \
  || echo "eval-gate-llm: notification dispatch errored (non-fatal); see logs above" >&2

# Stamp the dead-man's-switch heartbeat: record that the nightly mechanism ran
# to completion at all (pass OR fail). A separate, more-frequent heartbeat
# CronJob (deploy/helm/phi-audit/templates/eval-cronjob.yaml) pages on-call when
# this stamp goes stale — i.e. when the nightly job stopped running entirely and
# produces no other alert. If HEARTBEAT_PING_URL is set, --record also pings the
# external uptime monitor (healthchecks.io/Cronitor) with a success/fail signal —
# paired with the start ping above, this lets the monitor see a failed-but-alive
# run distinctly from a missed run, and a started-but-never-completed run as a
# hung one (see deploy/README.md → "External leg"). The gate exit code is passed
# so the external signal reflects pass vs fail. Recorded unconditionally and
# non-fatally so it never changes the job result (the gate exit code below is the
# source of truth).
echo "eval-gate-llm: recording dead-man's-switch heartbeat"
node "$ROOT/artifacts/api-server/evals/heartbeat.mjs" --record --exit-code="$gate_status" \
  || echo "eval-gate-llm: heartbeat record errored (non-fatal); see logs above" >&2

exit "$gate_status"
