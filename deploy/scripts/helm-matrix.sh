#!/usr/bin/env bash
# deploy/scripts/helm-matrix.sh
#
# CI lint+render matrix for the phi-audit Helm chart.
#
# Positive cases:  for each cloud overlay, render the chart with CI fixture
#                  values and assert kubectl-style output validity.
# Negative cases:  prove the fail-fast validators in _helpers.tpl actually
#                  reject the misconfigurations they're meant to catch.
#
# This script is meant to run in CI; locally, run it after any change under
# deploy/helm/. Requires `helm` (v3+) and `kubeconform` (optional — if
# present, every rendered manifest is also schema-validated).

set -euo pipefail

CHART_DIR="$(cd "$(dirname "$0")/../helm/phi-audit" && pwd)"
CI_DIR="$CHART_DIR/ci"
OUT_DIR="${OUT_DIR:-$(mktemp -d)}"
# Chart pins kubeVersion >=1.27 for HPA v2 + ingress.class field. Pass a
# concrete version so older helm clients (3.6.x in the dev nix shell) can
# render; production CI should use a modern helm and can drop this.
KUBE_VERSION="${KUBE_VERSION:-1.30.0}"
HELM_KV_FLAG="--kube-version=$KUBE_VERSION"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
heading() { printf '\n\033[1m%s\033[0m\n' "$1"; }

render() {
  local name=$1; shift
  local out="$OUT_DIR/$name.yaml"
  if ! helm template phi-audit "$CHART_DIR" $HELM_KV_FLAG "$@" >"$out" 2>"$OUT_DIR/$name.err"; then
    cat "$OUT_DIR/$name.err"
    fail "render: $name"
  fi
  # Sanity: must contain at least one Deployment and one Service.
  grep -q '^kind: Deployment' "$out" || fail "$name: no Deployment in render"
  grep -q '^kind: Service'    "$out" || fail "$name: no Service in render"
  pass "render: $name → $out ($(grep -c '^kind:' "$out") objects)"
  if command -v kubeconform >/dev/null 2>&1; then
    if kubeconform -strict -ignore-missing-schemas -summary "$out" >/dev/null; then
      pass "kubeconform: $name"
    else
      fail "kubeconform: $name (run manually for details)"
    fi
  fi
}

expect_fail() {
  local name=$1; shift
  local needle=$1; shift
  if helm template phi-audit "$CHART_DIR" $HELM_KV_FLAG "$@" >"$OUT_DIR/$name.out" 2>"$OUT_DIR/$name.err"; then
    fail "negative: $name — render unexpectedly SUCCEEDED"
  fi
  if ! grep -qF "$needle" "$OUT_DIR/$name.err"; then
    echo "--- actual stderr ---"
    cat "$OUT_DIR/$name.err"
    fail "negative: $name — expected message not found: $needle"
  fi
  pass "negative: $name (rejected with: $(echo "$needle" | cut -c1-60)…)"
}

# ---------------------------------------------------------------------------
# 1. helm lint each overlay
# ---------------------------------------------------------------------------
heading "[1/3] helm lint per overlay"
for cloud in aws gcp azure; do
  if helm lint "$CHART_DIR" \
      -f "$CHART_DIR/values.yaml" \
      -f "$CHART_DIR/values-$cloud.yaml" \
      -f "$CI_DIR/values-$cloud-ci.yaml" >"$OUT_DIR/lint-$cloud.out" 2>&1; then
    pass "lint: $cloud"
  else
    cat "$OUT_DIR/lint-$cloud.out"
    fail "lint: $cloud"
  fi
done

# ---------------------------------------------------------------------------
# 2. helm template each overlay (positive case)
# ---------------------------------------------------------------------------
heading "[2/3] helm template per overlay (positive)"
for cloud in aws gcp azure; do
  render "$cloud" \
    -f "$CHART_DIR/values.yaml" \
    -f "$CHART_DIR/values-$cloud.yaml" \
    -f "$CI_DIR/values-$cloud-ci.yaml"
done

# ---------------------------------------------------------------------------
# 3. fail-fast validators (negative cases)
# ---------------------------------------------------------------------------
heading "[2b/3] nightly eval CronJob (positive)"
# Enabling evalGate.nightly with a valid eval image must render a CronJob.
EVAL_OUT="$OUT_DIR/aws-eval.yaml"
if helm template phi-audit "$CHART_DIR" $HELM_KV_FLAG \
    -f "$CHART_DIR/values.yaml" \
    -f "$CHART_DIR/values-aws.yaml" \
    -f "$CI_DIR/values-aws-ci.yaml" \
    --set evalGate.nightly.enabled=true \
    --set evalGate.nightly.image.repository=example.dkr.ecr.us-east-1.amazonaws.com/phi-audit-eval \
    --set evalGate.nightly.image.tag=sha-deadbeef \
    --set evalGate.nightly.llmMinScore=0.5 >"$EVAL_OUT" 2>"$OUT_DIR/aws-eval.err"; then
  grep -q '^kind: CronJob' "$EVAL_OUT" || fail "eval-cronjob: no CronJob in render"
  grep -q 'EVAL_LLM_MIN_SCORE' "$EVAL_OUT" || fail "eval-cronjob: llmMinScore not wired to env"
  pass "render: aws + evalGate.nightly → CronJob present"
else
  cat "$OUT_DIR/aws-eval.err"
  fail "render: aws + evalGate.nightly"
fi
# Disabled by default: no CronJob in the standard render.
if grep -q '^kind: CronJob' "$OUT_DIR/aws.yaml"; then
  fail "eval-cronjob: CronJob rendered while evalGate.nightly disabled"
fi
pass "default: no CronJob when evalGate.nightly disabled"

# Sidecar-mode (GCP cloud-sql-proxy): the CronJob must carry the same DB
# connectivity sidecar as the api Deployment, declared as a NATIVE sidecar
# (initContainer + restartPolicy: Always) so the Job can still terminate.
EVAL_GCP_OUT="$OUT_DIR/gcp-eval.yaml"
if helm template phi-audit "$CHART_DIR" $HELM_KV_FLAG \
    -f "$CHART_DIR/values.yaml" \
    -f "$CHART_DIR/values-gcp.yaml" \
    -f "$CI_DIR/values-gcp-ci.yaml" \
    --set evalGate.nightly.enabled=true \
    --set evalGate.nightly.image.repository=us-docker.pkg.dev/example/phi-audit/phi-audit-eval \
    --set evalGate.nightly.image.tag=sha-deadbeef >"$EVAL_GCP_OUT" 2>"$OUT_DIR/gcp-eval.err"; then
  CRONJOB_DOC=$(awk '/^# Source: phi-audit\/templates\/eval-cronjob.yaml/{f=1} f{print} /^# Source/{if(f && $0 !~ /eval-cronjob/)exit}' "$EVAL_GCP_OUT")
  grep -q '^kind: CronJob' "$EVAL_GCP_OUT" || fail "eval-cronjob(gcp): no CronJob in render"
  printf '%s' "$CRONJOB_DOC" | grep -q 'initContainers:' || fail "eval-cronjob(gcp): sidecar missing from CronJob"
  printf '%s' "$CRONJOB_DOC" | grep -q 'restartPolicy: Always' || fail "eval-cronjob(gcp): sidecar not a native (Always-restart) sidecar"
  pass "render: gcp + evalGate.nightly → CronJob carries native DB sidecar"
else
  cat "$OUT_DIR/gcp-eval.err"
  fail "render: gcp + evalGate.nightly"
fi

# Heartbeat dead-man's-switch CronJob: enabling evalGate.heartbeat must render a
# SECOND CronJob (the --check job) that (a) reuses the nightly eval image, (b)
# carries the same native DB sidecar (GCP cloud-sql-proxy) so it can terminate,
# and (c) wires the channel config so a stale heartbeat can page on-call. Render
# on the gcp overlay (DB sidecar on) with channels + heartbeat enabled.
EVAL_HB_OUT="$OUT_DIR/gcp-eval-heartbeat.yaml"
if helm template phi-audit "$CHART_DIR" $HELM_KV_FLAG \
    -f "$CHART_DIR/values.yaml" \
    -f "$CHART_DIR/values-gcp.yaml" \
    -f "$CI_DIR/values-gcp-ci.yaml" \
    --set evalGate.nightly.image.repository=us-docker.pkg.dev/example/phi-audit/phi-audit-eval \
    --set evalGate.nightly.image.tag=sha-deadbeef \
    --set evalGate.heartbeat.enabled=true \
    --set channels.slack.enabled=true \
    --set channels.webhook.enabled=true >"$EVAL_HB_OUT" 2>"$OUT_DIR/gcp-eval-heartbeat.err"; then
  # Isolate just the eval-cronjob.yaml render, then narrow to the heartbeat doc
  # (the second `kind: CronJob` — nightly is disabled here, so it's the only one,
  # but match by name to stay robust if that changes).
  HB_DOC=$(awk '/name: phi-audit-eval-heartbeat$/{f=1} f && /^# Source:/{exit} f{print}' "$EVAL_HB_OUT")
  grep -q '^  name: phi-audit-eval-heartbeat$' "$EVAL_HB_OUT" || fail "eval-heartbeat: heartbeat CronJob not rendered"
  grep -q '^kind: CronJob' "$EVAL_HB_OUT" || fail "eval-heartbeat: no CronJob in render"
  # Disabled nightly → only the heartbeat CronJob should be present.
  grep -q '^  name: phi-audit-eval-nightly$' "$EVAL_HB_OUT" && fail "eval-heartbeat: nightly CronJob rendered while disabled"
  printf '%s' "$HB_DOC" | grep -q 'heartbeat.mjs' || fail "eval-heartbeat: --check command not wired"
  printf '%s' "$HB_DOC" | grep -q 'EVAL_HEARTBEAT_MAX_AGE_MINUTES' || fail "eval-heartbeat: maxAgeMinutes not wired to env"
  printf '%s' "$HB_DOC" | grep -q 'phi-audit/phi-audit-eval:sha-deadbeef' || fail "eval-heartbeat: nightly image not reused"
  printf '%s' "$HB_DOC" | grep -q 'initContainers:' || fail "eval-heartbeat: native DB sidecar missing"
  printf '%s' "$HB_DOC" | grep -q 'restartPolicy: Always' || fail "eval-heartbeat: sidecar not a native (Always-restart) sidecar"
  printf '%s' "$HB_DOC" | grep -q 'CHANNEL_SLACK_WEBHOOK_URL' || fail "eval-heartbeat: slack channel not wired"
  printf '%s' "$HB_DOC" | grep -q 'CHANNEL_WEBHOOK_URL' || fail "eval-heartbeat: webhook channel not wired"
  pass "render: gcp + evalGate.heartbeat → heartbeat CronJob (sidecar + channels) present"
else
  cat "$OUT_DIR/gcp-eval-heartbeat.err"
  fail "render: gcp + evalGate.heartbeat"
fi
# Disabled by default: no heartbeat CronJob in the standard render.
if grep -q '^  name: phi-audit-eval-heartbeat$' "$OUT_DIR/gcp.yaml"; then
  fail "eval-heartbeat: CronJob rendered while evalGate.heartbeat disabled"
fi
pass "default: no heartbeat CronJob when evalGate.heartbeat disabled"

heading "[3/3] negative cases (fail-fast validators must trip)"

# Nightly eval enabled without an eval image.
expect_fail "eval-missing-image" "evalGate.nightly.image.repository is required" \
  -f "$CHART_DIR/values.yaml" \
  -f "$CHART_DIR/values-aws.yaml" \
  -f "$CI_DIR/values-aws-ci.yaml" \
  --set evalGate.nightly.enabled=true

# Missing image tag.
expect_fail "missing-image-tag" "image.api.tag is required" \
  -f "$CHART_DIR/values.yaml" \
  -f "$CHART_DIR/values-aws.yaml" \
  --set image.api.repository=x \
  --set image.api.tag= \
  --set image.dashboard.repository=x \
  --set image.dashboard.tag=x \
  --set secrets.sessionSecret.existingSecret=s \
  --set secrets.notarizationSecret.existingSecret=n \
  --set database.existingSecret=d \
  --set ingress.host=h \
  --set logSource.cloudwatch.tenantId=t \
  --set logSource.cloudwatch.logGroups[0]=/a/b \
  --set logSource.cloudwatch.region=us-east-1

# Vertex without GCP_PROJECT_ID.
expect_fail "vertex-missing-project" "llm.gcp.projectId is required when llm.provider=vertex" \
  -f "$CHART_DIR/values.yaml" \
  -f "$CHART_DIR/values-gcp.yaml" \
  -f "$CI_DIR/values-gcp-ci.yaml" \
  --set llm.gcp.projectId=

# Cloud-SQL-Proxy with placeholder --help args.
expect_fail "sidecar-help-args" "database.sidecar.args is empty or contains --help" \
  -f "$CHART_DIR/values.yaml" \
  -f "$CHART_DIR/values-gcp.yaml" \
  -f "$CI_DIR/values-gcp-ci.yaml" \
  --set database.sidecar.args[0]=--help

# Bedrock without AWS_REGION.
expect_fail "bedrock-missing-region" "llm.aws.region is required when llm.provider=bedrock" \
  -f "$CHART_DIR/values.yaml" \
  -f "$CHART_DIR/values-aws.yaml" \
  -f "$CI_DIR/values-aws-ci.yaml" \
  --set llm.aws.region=

heading "OK — $OUT_DIR contains rendered manifests for inspection."
