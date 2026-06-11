{{/*
Common helpers.
*/}}

{{- define "phi-audit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phi-audit.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "phi-audit.api.fullname" -}}
{{- printf "%s-api" (include "phi-audit.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phi-audit.dashboard.fullname" -}}
{{- printf "%s-dashboard" (include "phi-audit.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phi-audit.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phi-audit.labels" -}}
helm.sh/chart: {{ include "phi-audit.chart" . }}
app.kubernetes.io/name: {{ include "phi-audit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "phi-audit.api.serviceAccountName" -}}
{{- if .Values.serviceAccount.api.create -}}
{{- default (printf "%s-api" (include "phi-audit.fullname" .)) .Values.serviceAccount.api.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.api.name -}}
{{- end -}}
{{- end -}}

{{- define "phi-audit.dashboard.serviceAccountName" -}}
{{- if .Values.serviceAccount.dashboard.create -}}
{{- default (printf "%s-dashboard" (include "phi-audit.fullname" .)) .Values.serviceAccount.dashboard.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.dashboard.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve channelSecret / llmSecret to sessionSecret.existingSecret when the
operator doesn't override them — keeps single-Secret installs ergonomic
while still allowing per-feature separation in production.
*/}}
{{- define "phi-audit.channelSecretName" -}}
{{- default .Values.secrets.sessionSecret.existingSecret .Values.secrets.channelSecret.existingSecret -}}
{{- end -}}

{{- define "phi-audit.llmSecretName" -}}
{{- default .Values.secrets.sessionSecret.existingSecret .Values.secrets.llmSecret.existingSecret -}}
{{- end -}}

{{- define "phi-audit.rawEvidenceSecretName" -}}
{{- default .Values.secrets.sessionSecret.existingSecret .Values.secrets.rawEvidenceSecret.existingSecret -}}
{{- end -}}

{{/*
Fail-fast validation. Required values that have no safe default.
*/}}
{{- define "phi-audit.validate" -}}
{{- if not .Values.image.api.repository -}}
{{- fail "image.api.repository is required (build with deploy/docker/api-server.Dockerfile and push to your registry)" -}}
{{- end -}}
{{- if not .Values.image.api.tag -}}
{{- fail "image.api.tag is required — pin to an immutable SHA tag" -}}
{{- end -}}
{{- if not .Values.image.dashboard.repository -}}
{{- fail "image.dashboard.repository is required" -}}
{{- end -}}
{{- if not .Values.image.dashboard.tag -}}
{{- fail "image.dashboard.tag is required" -}}
{{- end -}}
{{- if not .Values.secrets.sessionSecret.existingSecret -}}
{{- fail "secrets.sessionSecret.existingSecret is required — Secret with key `session-secret`" -}}
{{- end -}}
{{- if not .Values.secrets.notarizationSecret.existingSecret -}}
{{- fail "secrets.notarizationSecret.existingSecret is required — Secret with key `notarization-secret`. Per threat_model §23.2 this MUST be a DIFFERENT Secret (and ideally a different KMS/cloud account) than secrets.sessionSecret.existingSecret. To opt out of the split (dev only), set notarizationSecret.existingSecret to the same value as sessionSecret.existingSecret explicitly." -}}
{{- end -}}
{{- if and (not .Values.database.existingSecret) (not .Values.database.databaseUrl) -}}
{{- fail "database.existingSecret OR database.databaseUrl is required" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.host is required when ingress.enabled is true" -}}
{{- end -}}
{{/* Provider-specific required env */}}
{{- if eq .Values.llm.provider "vertex" -}}
{{- if not .Values.llm.gcp.projectId -}}
{{- fail "llm.gcp.projectId is required when llm.provider=vertex (GCP_PROJECT_ID — Vertex SDK requireEnv throws at boot without it)" -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.embedder.provider "vertex" -}}
{{- if not .Values.llm.gcp.projectId -}}
{{- fail "llm.gcp.projectId is required when embedder.provider=vertex (same GCP_PROJECT_ID env, used by both)" -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.llm.provider "bedrock" -}}
{{- if not .Values.llm.aws.region -}}
{{- fail "llm.aws.region is required when llm.provider=bedrock (AWS_REGION)" -}}
{{- end -}}
{{- end -}}
{{/* Azure OpenAI requires endpoint + api-key + deployment in the llmSecret
     (or the session secret if llmSecret is unset — see channelSecretName /
     llmSecretName helpers). The chart cannot inspect a Secret's keys at
     render time, so we at minimum require that *some* Secret name resolves
     so the secretKeyRef binding is well-formed; operator is responsible for
     populating the three keys per deploy/README.md. */}}
{{- if eq .Values.llm.provider "azure-openai" -}}
{{- if not (include "phi-audit.llmSecretName" .) -}}
{{- fail "llm.provider=azure-openai requires secrets.llmSecret.existingSecret (or secrets.sessionSecret.existingSecret as fallback) with keys: azure-openai-endpoint, azure-openai-api-key, azure-openai-deployment" -}}
{{- end -}}
{{- end -}}
{{/* Sidecar placeholder-args guard */}}
{{- if .Values.database.sidecar.enabled -}}
{{- if or (eq (len .Values.database.sidecar.args) 0) (has "--help" .Values.database.sidecar.args) -}}
{{- fail "database.sidecar.args is empty or contains --help. The sidecar would exit and silently break the DB path. Set real args (e.g. cloud-sql-proxy: --auto-iam-authn, <project:region:instance>, --port=5432)." -}}
{{- end -}}
{{- end -}}
{{/* logSource sanity */}}
{{- if and .Values.logSource.enabled (eq .Values.logSource.type "cloudwatch") -}}
{{- if not .Values.logSource.cloudwatch.tenantId -}}{{- fail "logSource.cloudwatch.tenantId is required when logSource.enabled=true" -}}{{- end -}}
{{- if eq (len .Values.logSource.cloudwatch.logGroups) 0 -}}{{- fail "logSource.cloudwatch.logGroups is required when logSource.enabled=true" -}}{{- end -}}
{{- if not .Values.logSource.cloudwatch.region -}}{{- fail "logSource.cloudwatch.region is required when logSource.enabled=true" -}}{{- end -}}
{{- end -}}
{{/* Raw-evidence WORM store sanity. Default-inert: only validates once a
     provider is selected. Turning it on is a one-location overlay change. */}}
{{- if .Values.rawEvidence.provider -}}
{{- $p := .Values.rawEvidence.provider -}}
{{- if not (or (eq $p "s3") (eq $p "gcs") (eq $p "azure-blob")) -}}
{{- fail (printf "rawEvidence.provider must be one of: s3 | gcs | azure-blob (got %q; empty → inline database default)" $p) -}}
{{- end -}}
{{- if eq $p "s3" -}}
{{- if not .Values.rawEvidence.s3.bucket -}}{{- fail "rawEvidence.s3.bucket is required when rawEvidence.provider=s3 (RAW_EVIDENCE_S3_BUCKET)" -}}{{- end -}}
{{- if and (not .Values.llm.aws.region) (not .Values.rawEvidence.s3.region) (not (and .Values.logSource.enabled (eq .Values.logSource.type "cloudwatch") .Values.logSource.cloudwatch.region)) -}}
{{- fail "rawEvidence.provider=s3 needs an AWS region (AWS_REGION). Set llm.aws.region (Bedrock deployments) or rawEvidence.s3.region." -}}
{{- end -}}
{{- if and .Values.rawEvidence.s3.objectLockMode (not (or (eq .Values.rawEvidence.s3.objectLockMode "COMPLIANCE") (eq .Values.rawEvidence.s3.objectLockMode "GOVERNANCE"))) -}}
{{- fail (printf "rawEvidence.s3.objectLockMode must be COMPLIANCE or GOVERNANCE (got %q)" .Values.rawEvidence.s3.objectLockMode) -}}
{{- end -}}
{{- end -}}
{{- if eq $p "gcs" -}}
{{- if not .Values.rawEvidence.gcs.bucket -}}{{- fail "rawEvidence.gcs.bucket is required when rawEvidence.provider=gcs (RAW_EVIDENCE_GCS_BUCKET)" -}}{{- end -}}
{{- end -}}
{{- if eq $p "azure-blob" -}}
{{- if not .Values.rawEvidence.azure.container -}}{{- fail "rawEvidence.azure.container is required when rawEvidence.provider=azure-blob (RAW_EVIDENCE_AZURE_CONTAINER)" -}}{{- end -}}
{{- if not (include "phi-audit.rawEvidenceSecretName" .) -}}{{- fail "rawEvidence.provider=azure-blob requires secrets.rawEvidenceSecret.existingSecret (or secrets.sessionSecret.existingSecret fallback) holding key raw-evidence-azure-connection-string" -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- if and .Values.rawEvidence.tiering.ageDays (not .Values.rawEvidence.provider) -}}
{{- fail "rawEvidence.tiering.ageDays needs an external rawEvidence.provider — tiering moves inline raw INTO the WORM store, so it is a no-op without one" -}}
{{- end -}}
{{/* Nightly eval gate needs its own (eval-target) image — the slim api runtime
     image has no pnpm/vitest and cannot run the suites. */}}
{{- if .Values.evalGate.nightly.enabled -}}
{{- if not .Values.evalGate.nightly.image.repository -}}
{{- fail "evalGate.nightly.image.repository is required when evalGate.nightly.enabled=true (build with: docker build -f deploy/docker/api-server.Dockerfile --target eval -t <registry>/phi-audit-eval:<sha> .)" -}}
{{- end -}}
{{- if not .Values.evalGate.nightly.image.tag -}}
{{- fail "evalGate.nightly.image.tag is required when evalGate.nightly.enabled=true — pin to an immutable SHA tag" -}}
{{- end -}}
{{/* The heartbeat ping URL is hit ONLY by the nightly --record run, so a
     missing `key` would render a broken secretKeyRef (the container would fail
     to start). Catch it here while the nightly job is actually enabled. */}}
{{- if and .Values.evalGate.nightly.heartbeatPing.existingSecret (not .Values.evalGate.nightly.heartbeatPing.key) -}}
{{- fail "evalGate.nightly.heartbeatPing.key is empty but heartbeatPing.existingSecret is set — the external-ping secretKeyRef would be incomplete. Set heartbeatPing.key to the key holding the ping URL (default: heartbeat-ping-url)." -}}
{{- end -}}
{{- end -}}
{{/* External outage-ping misconfiguration guard. The heartbeat ping URL is hit
     ONLY by the nightly job's --record leg; configuring it while the nightly job
     is DISABLED yields a permanently-silent external monitor — it is never
     pinged, so it pages "missing" forever (or, worse, lulls you into believing
     cluster-down is covered when nothing will ever ping it). This is the one
     failure the in-cluster checker cannot see, so a dead external monitor is a
     real gap, not cosmetic. Fail fast so it is caught at install, not mid-
     incident. Fully inert when heartbeatPing.existingSecret is empty (the
     default — no external ping configured). */}}
{{- if and .Values.evalGate.nightly.heartbeatPing.existingSecret (not .Values.evalGate.nightly.enabled) -}}
{{- fail "evalGate.nightly.heartbeatPing.existingSecret is set but evalGate.nightly.enabled=false — only the nightly --record run ever pings that URL, so the external dead-man's switch would never fire and on-call would have no cluster-down coverage. Enable the nightly job (evalGate.nightly.enabled=true + its eval image), or clear heartbeatPing.existingSecret to opt out of the external ping." -}}
{{- end -}}
{{- end -}}
