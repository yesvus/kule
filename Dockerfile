# Build the published multi-arch application image in CI. Deploy ONLY by the
# resulting verified OCI index digest (linux/arm64 present), never by a tag.
FROM python:3.13.9-slim-bookworm AS wheelhouse
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheelhouse .

# Maintained upstream Kubernetes MCP implementation, pinned to an immutable
# multiarch OCI index (ARM64 + AMD64); no secondary Pod or public listener.
FROM ghcr.io/containers/kubernetes-mcp-server@sha256:49928106385d3b17697a12c85805e8c377359173491aaa54d91d53a90d058933 AS kubernetes-upstream

FROM python:3.13.9-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --gid 10001 operator-mcp \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent operator-mcp
COPY --from=wheelhouse /wheelhouse /wheelhouse
COPY --from=kubernetes-upstream /app/kubernetes-mcp-server /usr/local/bin/kubernetes-mcp-server
# Exercise the pinned Go binary under each target architecture during CI build.
RUN /usr/local/bin/kubernetes-mcp-server --version >/dev/null
COPY contrib/kubernetes-upstream.toml /usr/local/share/kule/kubernetes-upstream.toml
COPY contrib/kubernetes-workspace.toml /usr/local/share/kule/kubernetes-workspace.toml
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse operator-mcp \
    && rm -rf /wheelhouse
USER 10001:10001
EXPOSE 8795
ENTRYPOINT ["operator-mcp"]
CMD ["serve", "--config", "/etc/operator-mcp/config.toml"]
