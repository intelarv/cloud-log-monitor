# Multi-stage build for @workspace/dashboard — Vite SPA served by nginx.
# Static assets only. All API calls route to /api which the Ingress sends
# to the api-server Service (see deploy/helm/phi-audit/templates/ingress.yaml).

ARG NODE_VERSION=24-bookworm-slim
ARG NGINX_VERSION=1.27-alpine

FROM node:${NODE_VERSION} AS builder
WORKDIR /repo
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.json ./
COPY lib ./lib
COPY artifacts/dashboard ./artifacts/dashboard
COPY scripts ./scripts

RUN pnpm install --frozen-lockfile --filter @workspace/dashboard... --filter @workspace/scripts...

# Dashboard expects BASE_PATH for Vite's `base` (see artifacts/dashboard/vite.config.ts).
# Production serves at "/" — the api-server is the one mounted at /api.
ENV BASE_PATH=/ \
    PORT=4173
RUN pnpm --filter @workspace/dashboard run build

# ---------------------------------------------------------------------------

FROM nginx:${NGINX_VERSION} AS runtime

# Drop the default nginx config; ours adds SPA fallback + security headers +
# cache headers. Run as non-root by switching to the `nginx` user
# (already exists in the base image).
RUN rm /etc/nginx/conf.d/default.conf
COPY deploy/docker/dashboard-nginx.conf /etc/nginx/conf.d/dashboard.conf
COPY --from=builder /repo/artifacts/dashboard/dist /usr/share/nginx/html

# nginx:alpine listens on 8080 here (non-privileged); 80 would require root.
# Permit nginx (uid 101) to write its pid/cache without escalating from 8080.
RUN chown -R nginx:nginx /var/cache/nginx /var/run /usr/share/nginx/html \
 && chmod -R g+w /var/cache/nginx /var/run
USER nginx
EXPOSE 8080

# Liveness — nginx serves /healthz as a tiny static file.
RUN printf 'ok\n' > /usr/share/nginx/html/healthz

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:8080/healthz || exit 1
