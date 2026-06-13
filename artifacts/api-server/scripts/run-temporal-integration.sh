#!/usr/bin/env bash
# Run the live-cluster Temporal integration test against a locally-started
# `temporal server start-dev` (single-binary dev server, no Docker required).
#
# This is the on-demand verification harness for the Temporal orchestration
# backend (WORKFLOW_ENGINE=temporal). The normal `vitest run` suite and the
# eval gate skip temporal-integration.test.ts (gated on TEMPORAL_INTEGRATION=1),
# so this script is the only thing that exercises the real @temporalio/* SDK
# against a real server. Requires the optional @temporalio/* deps to be
# installed (pnpm --filter @workspace/api-server add -O @temporalio/client
# @temporalio/worker @temporalio/workflow).
set -euo pipefail

PORT="${TEMPORAL_TEST_PORT:-7233}"
ADDRESS="127.0.0.1:${PORT}"
DBFILE="$(mktemp /tmp/temporal-dev-XXXXXX.db)"
LOGFILE="$(mktemp /tmp/temporal-dev-XXXXXX.log)"
# start-dev creates the SQLite db itself; hand it a fresh path, not the empty
# placeholder mktemp just allocated (it errors if the file already exists).
rm -f "${DBFILE}"

# Locate the `temporal` CLI: prefer PATH, else search the Nix store (Replit).
TEMPORAL_BIN="$(command -v temporal || true)"
if [[ -z "${TEMPORAL_BIN}" ]]; then
  TEMPORAL_BIN="$(find /nix/store -maxdepth 2 -type f -name temporal -path '*temporal-cli*/bin/*' 2>/dev/null | head -n1 || true)"
fi
if [[ -z "${TEMPORAL_BIN}" ]]; then
  echo "ERROR: 'temporal' CLI not found on PATH or in /nix/store." >&2
  echo "Install the Temporal CLI (https://docs.temporal.io/cli) and retry." >&2
  exit 1
fi
echo "Using temporal CLI: ${TEMPORAL_BIN}"

"${TEMPORAL_BIN}" server start-dev \
  --headless \
  --ip 127.0.0.1 \
  --port "${PORT}" \
  --db-filename "${DBFILE}" \
  --log-level error >"${LOGFILE}" 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" 2>/dev/null || true
  rm -f "${DBFILE}" "${LOGFILE}" || true
}
trap cleanup EXIT

# Wait for the gRPC port to accept connections.
echo "Waiting for Temporal dev server on ${ADDRESS} ..."
for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    exec 3>&- || true
    READY=1
    break
  fi
  sleep 0.5
done
if [[ "${READY:-0}" != "1" ]]; then
  echo "ERROR: Temporal dev server did not become ready. Log:" >&2
  cat "${LOGFILE}" >&2 || true
  exit 1
fi
echo "Temporal dev server is up."

# Run only the integration spec, with the gate enabled.
cd "$(dirname "$0")/.."
TEMPORAL_INTEGRATION=1 TEMPORAL_ADDRESS="${ADDRESS}" \
  pnpm exec vitest run src/lib/agents/temporal-integration.test.ts "$@"
