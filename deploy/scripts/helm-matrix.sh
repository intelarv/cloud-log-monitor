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
heading "[3/3] negative cases (fail-fast validators must trip)"

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
