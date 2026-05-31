---
name: DB sidecar in Helm Jobs/CronJobs must be native
description: Why the eval CronJob declares the cloud-sql-proxy as an initContainer, not a plain sidecar
---

# DB sidecar in a Helm Job/CronJob must be a native sidecar

The api Deployment runs its DB connectivity proxy (GCP cloud-sql-proxy, optional
AWS rds-iam-auth-token) as an ordinary container — fine for a long-running Pod.
Any **Job/CronJob** that needs the same DB access (e.g. the nightly eval gate)
must declare that proxy as a **native sidecar**: an entry under `initContainers`
with `restartPolicy: Always`.

**Why:** a plain sidecar container never exits, so a Job's Pod stays `Running`
after the main container finishes — the Job only ends when `activeDeadlineSeconds`
kills it as DeadlineExceeded, i.e. every run "fails". A native sidecar
(`initContainer` + `restartPolicy: Always`, GA since k8s 1.29) is auto-stopped by
the kubelet once the main containers complete, so the Job terminates cleanly.

**How to apply:** when mirroring api-deployment DB config into any Job/CronJob,
gate the sidecar on `database.sidecar.enabled` and emit it under `initContainers`
with `restartPolicy: Always` (not under `containers`). The eval CronJob in
`deploy/helm/phi-audit/templates/eval-cronjob.yaml` is the reference; the
GCP-overlay render is asserted in `deploy/scripts/helm-matrix.sh`.
