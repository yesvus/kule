# Build the published multi-arch application image in CI. Deploy ONLY by the
# resulting verified OCI index digest (linux/arm64 present), never by a tag.
FROM python:3.13.9-slim-bookworm AS wheelhouse
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheelhouse .

FROM python:3.13.9-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --gid 10001 operator-mcp \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent operator-mcp
COPY --from=wheelhouse /wheelhouse /wheelhouse
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse operator-mcp \
    && rm -rf /wheelhouse
USER 10001:10001
EXPOSE 8795
ENTRYPOINT ["operator-mcp"]
CMD ["serve", "--config", "/etc/operator-mcp/config.toml"]
