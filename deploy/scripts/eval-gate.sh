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

echo "eval-gate: running deterministic eval suites + regression gate"
pnpm --filter @workspace/api-server run eval
echo "eval-gate: OK"
