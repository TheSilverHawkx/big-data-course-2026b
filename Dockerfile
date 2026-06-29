FROM python:3.12.13-slim-bookworm

# ca-certificates: HTTPS for NVD/CISA/GitHub
# curl: health checks
# openjdk-17-jre-headless: required by PySpark
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    PATH="${JAVA_HOME}/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_COMPILE_BYTECODE=1

COPY --from=ghcr.io/astral-sh/uv:0.5.18 /uv /usr/local/bin/uv

WORKDIR /app

# Layer-cache-friendly: copy manifests first, sync deps only, then copy source.
# README.md is referenced by pyproject (readme=...) so it must be present.
COPY pyproject.toml uv.lock README.md ./

# --frozen: fail if uv.lock is stale; --all-extras: includes the notebook extra.
# --no-install-project: cache the heavy deps layer without the local package.
RUN uv sync --frozen --all-extras --no-install-project

COPY src/ ./src/
COPY config/ ./config/

# Install the riskrank package itself now that the source is present.
RUN uv sync --frozen --all-extras

ENV PATH="/app/.venv/bin:${PATH}"

CMD ["sleep", "infinity"]
