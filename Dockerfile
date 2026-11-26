# Build the published multi-arch application image in CI. Deploy ONLY by the
# resulting verified OCI index digest (linux/arm64 present), never by a tag.
FROM python:3.15.2-slim-bookworm AS wheelhouse
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheelhouse .

# Maintained upstream Kubernetes MCP implementation, pinned to an immutable
# multiarch OCI index (ARM64 + AMD64); no secondary Pod or public listener.
FROM ghcr.io/containers/kubernetes-mcp-server@sha256:49928106385d3b17697a12c85805e8c377359173491aaa54d91d53a90d058933 AS kubernetes-upstream

# Argo Project Labs MCP upstream, version-pinned and stdio-only.
FROM node:26.13.0-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS argocd-upstream
COPY contrib/argocd-mcp/package.json contrib/argocd-mcp/package-lock.json /opt/argocd-mcp/
RUN cd /opt/argocd-mcp && npm ci --omit=dev --ignore-scripts --no-audit --no-fund
RUN test -f /opt/argocd-mcp/node_modules/argocd-mcp/dist/index.js

FROM python:3.15.2-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 kule \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent kule
COPY --from=wheelhouse /wheelhouse /wheelhouse
COPY --from=kubernetes-upstream /app/kubernetes-mcp-server /usr/local/bin/kubernetes-mcp-server
# Exercise the pinned Go binary under each target architecture during CI build.
RUN /usr/local/bin/kubernetes-mcp-server --version >/dev/null
COPY --from=argocd-upstream /usr/local/bin/node /usr/local/bin/node
COPY --from=argocd-upstream /opt/argocd-mcp/node_modules /opt/argocd-mcp/node_modules
COPY contrib/kubernetes-upstream.toml /usr/local/share/kule/kubernetes-upstream.toml
COPY contrib/kubernetes-workspace.toml /usr/local/share/kule/kubernetes-workspace.toml
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse kule \
    && rm -rf /wheelhouse \
    && node --version >/dev/null
COPY examples/config.example.toml /tmp/kule-config-smoke.toml
# Run the installed CLI under each image architecture, not just the host CI interpreter.
RUN python -m pip check \
    && kule --help >/dev/null \
    && KULE_OIDC_CLIENT_SECRET=ci-placeholder \
       KULE_JWT_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
       kule check-config --config /tmp/kule-config-smoke.toml \
    && rm -f /tmp/kule-config-smoke.toml
USER 10001:10001
EXPOSE 8795
ENTRYPOINT ["kule"]
CMD ["serve", "--config", "/etc/kule/config.toml"]
