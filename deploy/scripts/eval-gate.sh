#!/usr/bin/env bash
# CI quality gate for the PHI/PII detectors, redactor, agent-defense policy, and
# chat-agent citation parser. Runs the six deterministic (credential-free) eval
# suites and the regression gate (evals/gate.mjs) against evals/baseline.json.
# A regression greater than the gate's 5-point tolerance fails the build.
#
# This is the automatic, secret-free half of the eval suite. The two
# LLM/DB-backed suites (citation-live, agent-agreement) stay opt-in behind
# EVAL_LLM=1 and are NOT run here — see deploy/scripts/eval-gate-llm.sh for the
# nightly/manual job that runs them where credentials are available.
#
# Mirrors deploy/scripts/helm-matrix.sh + deploy/scripts/tf-fmt-check.sh: a
# fast, deterministic gate suitable for running on every change.

set -euo pipefail

# The deterministic suites transitively import lib/db, which throws at module
# load time if DATABASE_URL is unset. They never open a connection, so a
# placeholder satisfies the import without needing a real database. Real values
# (when present in the dev shell) are left untouched — the suites still never
# connect. SESSION_SECRET is required by the same boot-config path.
: "${DATABASE_URL:=postgres://placeholder:placeholder@127.0.0.1:5432/placeholder}"
: "${SESSION_SECRET:=eval-gate-placeholder-session-secret}"
export DATABASE_URL SESSION_SECRET

# Hard-guarantee the credential-free contract: never let an ambient EVAL_LLM
# pull the live LLM/DB suites into this gate.
unset EVAL_LLM

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Per-change external heartbeat (opt-in). When HEARTBEAT_PING_URL is set, this
# fast, frequent gate becomes its own external dead-man's switch: a --start ping
# before the run and a success/fail --record after let an external monitor
# (healthchecks.io / Cronitor) alert when a per-change run begins but never
# completes (a hung suite, a wedged process, a killed CI runner), distinctly from
# one that simply never ran. This is the per-change parallel of the nightly job's
# external leg in eval-gate-llm.sh.
#
# Scoped apart from the nightly switch on two axes so the two never cross-signal:
#   - Identity: EVAL_HEARTBEAT_NAME defaults to "per-change" (the nightly job
#     uses "nightly"), so each maps to its own external monitor / check.
#   - Transport: this gate is DB-free (it runs against a placeholder
#     DATABASE_URL), so the heartbeat is invoked with DATABASE_URL unset — only
#     the external ping leg runs; no connection is attempted and the in-cluster
#     row (owned by the nightly job) is never touched.
# Fully inert when HEARTBEAT_PING_URL is unset (local + default CI runs page
# nothing), and every heartbeat call is best-effort + non-fatal so it can never
# block or change the gate result.
HEARTBEAT="$ROOT/artifacts/api-server/evals/heartbeat.mjs"
heartbeat_enabled=false
if [[ -n "${HEARTBEAT_PING_URL:-}" ]]; then
  heartbeat_enabled=true
  export EVAL_HEARTBEAT_NAME="${EVAL_HEARTBEAT_NAME:-per-change}"
  echo "eval-gate: signalling external heartbeat start (gate '${EVAL_HEARTBEAT_NAME}')"
  env -u DATABASE_URL node "$HEARTBEAT" --start \
    || echo "eval-gate: heartbeat start errored (non-fatal); see logs above" >&2
fi

echo "eval-gate: running deterministic eval suites + regression gate"
# Preserve the gate's exit code so the heartbeat can report pass vs fail before
# we exit with it.
set +e
pnpm --filter @workspace/api-server run eval
gate_status=$?
set -e

if [[ $gate_status -eq 0 ]]; then
  echo "eval-gate: OK"
else
  echo "eval-gate: gate FAILED (exit ${gate_status})" >&2
fi

if [[ "$heartbeat_enabled" == true ]]; then
  echo "eval-gate: recording external heartbeat (exit ${gate_status})"
  env -u DATABASE_URL node "$HEARTBEAT" --record --exit-code="$gate_status" \
    || echo "eval-gate: heartbeat record errored (non-fatal); see logs above" >&2
fi

exit "$gate_status"
