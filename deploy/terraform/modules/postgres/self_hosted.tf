# Self-hosted branch — no resources, just passthrough.
#
# Use cases:
# - Operator-managed Postgres (CNPG operator, Crunchy, Stackgres)
# - Existing RDS/Cloud SQL/Azure DB not managed by this module
# - Local dev / Replit dev DB
#
# The module's contract is the same: the same outputs (host, port, db,
# username, DATABASE_URL, secret_ref) are emitted in all branches so the
# downstream Helm chart values can be wired identically.

# Nothing to define here — `outputs.tf` reads `var.self_hosted` directly when
# `local.is_self_hosted` is true.
