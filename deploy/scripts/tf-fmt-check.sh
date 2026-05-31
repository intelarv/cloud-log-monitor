#!/usr/bin/env bash
# Lightweight Terraform/OpenTofu format check for the deploy/terraform tree.
# Heavy `tofu validate` (which needs `tofu init` + ~500MB of provider plugins)
# runs in CI, not in this fast local gate. Mirrors deploy/scripts/helm-matrix.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)/terraform"

if command -v tofu >/dev/null 2>&1; then
  BIN=tofu
elif command -v terraform >/dev/null 2>&1; then
  BIN=terraform
elif [[ -x "$(dirname "$0")/../../.local/bin/tofu" ]]; then
  BIN="$(dirname "$0")/../../.local/bin/tofu"
else
  echo "tf-fmt-check: no tofu or terraform binary found on PATH; skipping." >&2
  exit 0
fi

echo "tf-fmt-check: using $BIN ($($BIN version | head -1))"
echo "tf-fmt-check: checking $ROOT"

# `-diff` makes drift visible in CI logs; `-check` flips exit code on drift.
"$BIN" fmt -recursive -check -diff "$ROOT"
echo "tf-fmt-check: OK"
