# ─── Global version pins (single source of truth) ────────────────────────────
# Dependabot tracks all ARGs below via the FROM lines that reference them.
# To override at build time: docker build --build-arg TRIVY_VERSION=0.70.0 .
#
# Dependabot-trackable (each has a corresponding FROM <image>:<ARG> stage):
ARG PYTHON_VERSION=3.12
ARG TRUFFLEHOG_VERSION=3.93.8
ARG TRIVY_VERSION=0.69.3
ARG UV_VERSION=0.10.11
#
# NOT Dependabot-trackable (no official Docker image with a stable binary path):
ARG OPENGREP_VERSION=v1.16.5

# ─── Stage: trivy (Dependabot-trackable) ──────────────────────────────────────
# FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

# ─── Stage: trufflehog (Dependabot-trackable) ─────────────────────────────────
FROM trufflesecurity/trufflehog:${TRUFFLEHOG_VERSION} AS trufflehog

# ─── Stage: uv (Dependabot-trackable) ─────────────────────────────────────────
# Named stage required — COPY --from does not support ARG variable expansion.
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ─── Stage: opengrep-installer ────────────────────────────────────────────────
# OpenGrep does not publish an official Docker image with a stable binary path,
# so we install via their official script in a dedicated build stage.
# NOTE: OPENGREP_VERSION is not Dependabot-trackable; update manually above.
FROM python:${PYTHON_VERSION}-slim AS opengrep-installer
ARG OPENGREP_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates bash
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh \
    | bash -s -- -v "${OPENGREP_VERSION}"

# ─── Stage: runtime ───────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

WORKDIR /socket-basics

COPY --from=uv /uv /uvx /bin/

# Binary tools from immutable build stages
# COPY --from=trivy      /usr/local/bin/trivy      /usr/local/bin/trivy
COPY --from=trufflehog /usr/bin/trufflehog        /usr/local/bin/trufflehog
COPY --from=opengrep-installer /root/.opengrep    /root/.opengrep

# System deps + Node.js 22.x + Socket CLI
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl git wget ca-certificates
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs
RUN --mount=type=cache,target=/root/.npm \
    npm install -g socket

# Python project files
COPY socket_basics  /socket-basics/socket_basics
COPY pyproject.toml README.md LICENSE uv.lock /socket-basics/

# Install Python deps (uv cache speeds up repeated local builds)
ENV UV_LINK_MODE=copy
RUN --mount=type=cache,target=/root/.cache/uv \
    pip install -e . && uv sync --frozen --no-dev

# OCI image labels — baked-in tool versions + build provenance
# Values are populated by the publish-docker workflow; local builds use defaults.
ARG SOCKET_BASICS_VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG TRIVY_VERSION
ARG TRUFFLEHOG_VERSION
ARG OPENGREP_VERSION
LABEL org.opencontainers.image.title="Socket Basics" \
      org.opencontainers.image.source="https://github.com/SocketDev/socket-basics" \
      org.opencontainers.image.version="${SOCKET_BASICS_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      com.socket.trivy-version="${TRIVY_VERSION}" \
      com.socket.trufflehog-version="${TRUFFLEHOG_VERSION}" \
      com.socket.opengrep-version="${OPENGREP_VERSION}"

ENV PATH="/socket-basics/.venv/bin:/root/.opengrep/cli/latest:/usr/local/bin:$PATH"

ENTRYPOINT ["socket-basics"]