# Multi-stage build for @workspace/api-server.
#
# Stage 1: install workspace deps + run esbuild bundle (dist/index.mjs).
# Stage 2: copy bundle into a slim runtime image. The bundle externalizes
# native + cloud SDK packages (see artifacts/api-server/build.mjs); they
# come along via node_modules in the runtime stage. Cloud SDKs are loaded
# at runtime via loadOptional() only when LLM_PROVIDER / EMBEDDING_PROVIDER
# / LOG_SOURCE selects them — image carries them so we don't need separate
# per-cloud images.

ARG NODE_VERSION=24-bookworm-slim

FROM node:${NODE_VERSION} AS builder
WORKDIR /repo

# Enable pnpm via corepack (pinned in package.json's packageManager field).
RUN corepack enable

# Copy workspace plumbing first to maximize layer caching.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.json ./
COPY lib ./lib
COPY artifacts/api-server ./artifacts/api-server
COPY scripts ./scripts

# Frozen install — the lockfile is the contract.
RUN pnpm install --frozen-lockfile --filter @workspace/api-server... --filter @workspace/scripts...

# Build the api-server bundle. typecheck:libs first so composite libs emit
# their .d.ts files; then the leaf bundle via esbuild.
RUN pnpm run typecheck:libs \
 && pnpm --filter @workspace/api-server run build

# Prune to production deps for the runtime image. We re-run install with
# --prod so devDependencies (esbuild, typescript, vitest...) don't ship.
RUN pnpm --filter @workspace/api-server deploy --prod /repo/deploy-out

# ---------------------------------------------------------------------------
# Optional CI / nightly-eval image. Unlike the slim `runtime` stage below this
# keeps the FULL workspace + devDependencies (pnpm, vitest, the eval suites)
# so it can run `pnpm run eval:gate:llm`. This is NOT a production image —
# build + push it under a separate tag and point the Helm CronJob
# (evalGate.nightly in deploy/helm/phi-audit) at it:
#
#   docker build -f deploy/docker/api-server.Dockerfile --target eval \
#     -t <registry>/phi-audit-eval:<sha> .
#
# At run time it needs DATABASE_URL + a configured LLM runtime (LLM_PROVIDER +
# creds); the CronJob injects them from the same Secrets the API uses.
# ---------------------------------------------------------------------------
FROM builder AS eval
WORKDIR /repo

# Non-root, matching the runtime image. The builder created /repo as root; hand
# it to the unprivileged user so the eval run can write evals/results (a cache).
RUN groupadd --system --gid 10001 phiaudit \
 && useradd  --system --uid 10001 --gid phiaudit --home-dir /repo --shell /usr/sbin/nologin phiaudit \
 && chown -R phiaudit:phiaudit /repo
USER phiaudit

ENV NODE_ENV=production \
    NODE_OPTIONS="--enable-source-maps"

# EVAL_LLM=1 is set inside eval-gate-llm.sh; floor via EVAL_LLM_MIN_SCORE env.
CMD ["pnpm", "run", "eval:gate:llm"]

# ---------------------------------------------------------------------------

FROM node:${NODE_VERSION} AS runtime
WORKDIR /app

# Non-root user. The threat model requires the container not run as root.
RUN groupadd --system --gid 10001 phiaudit \
 && useradd  --system --uid 10001 --gid phiaudit --home-dir /app --shell /usr/sbin/nologin phiaudit

# Bundle + its (production-only) node_modules from the deploy-out folder
# pnpm created — this contains the externalized cloud SDKs the bundle
# imports at runtime (Bedrock, Vertex auth lib, CloudWatch Logs SDK).
COPY --from=builder --chown=phiaudit:phiaudit /repo/deploy-out /app

# Drop privileges.
USER phiaudit

ENV NODE_ENV=production \
    PORT=8080 \
    NODE_OPTIONS="--enable-source-maps"

EXPOSE 8080

# Readiness/liveness use /api/healthz (mounted in artifacts/api-server/src/app.ts).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--enable-source-maps", "dist/index.mjs"]
