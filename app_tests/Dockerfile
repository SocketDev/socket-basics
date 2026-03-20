# syntax=docker/dockerfile:1

# ─── Global version pins (single source of truth) ────────────────────────────
# Dependabot tracks all ARGs below via the FROM lines that reference them.
# To override at build time: docker build --build-arg TRIVY_VERSION=0.70.0 .
#
# Dependabot-trackable (each has a corresponding FROM <image>:<ARG> stage):
ARG GOLANG_VERSION=1.24.1
ARG NODE_VERSION=22
ARG PYTHON_VERSION=3.12
ARG TRUFFLEHOG_VERSION=3.93.8
ARG TRIVY_VERSION=0.69.3
ARG UV_VERSION=0.10.11
#
# NOT Dependabot-trackable (no official Docker image with a stable binary path):
ARG GOSEC_VERSION=v2.24.7
ARG OPENGREP_VERSION=v1.16.5

# ─── Stage: trivy (Dependabot-trackable) ──────────────────────────────────────
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

# ─── Stage: trufflehog (Dependabot-trackable) ─────────────────────────────────
FROM trufflesecurity/trufflehog:${TRUFFLEHOG_VERSION} AS trufflehog

# ─── Stage: golang (Dependabot-trackable) ─────────────────────────────────────
FROM golang:${GOLANG_VERSION} AS golang

# ─── Stage: node (Dependabot-trackable) ───────────────────────────────────────
# Named stage replaces the nodesource curl install, making the Node version
# Dependabot-trackable via the FROM line.
FROM node:${NODE_VERSION}-slim AS node

# ─── Stage: uv (Dependabot-trackable) ─────────────────────────────────────────
# Named stage required — COPY --from does not support ARG variable expansion.
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ─── Stage: gosec-installer ───────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS gosec-installer
ARG GOSEC_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates
RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh \
    | sh -s -- -b /usr/local/bin "${GOSEC_VERSION}"

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

WORKDIR /socket-security-tools
ENV PATH=$PATH:/usr/local/go/bin

COPY --from=uv /uv /uvx /bin/

# Binary tools from immutable build stages
COPY --from=trivy           /usr/local/bin/trivy      /usr/local/bin/trivy
COPY --from=trufflehog      /usr/bin/trufflehog        /usr/local/bin/trufflehog
COPY --from=opengrep-installer /root/.opengrep         /root/.opengrep
COPY --from=golang          /usr/local/go              /usr/local/go
COPY --from=gosec-installer /usr/local/bin/gosec       /usr/local/bin/gosec

# Node binary + npm from the versioned node stage (Dependabot-trackable)
COPY --from=node /usr/local/bin/node          /usr/local/bin/node
COPY --from=node /usr/local/bin/npm           /usr/local/bin/npm
COPY --from=node /usr/local/bin/npx           /usr/local/bin/npx
COPY --from=node /usr/local/lib/node_modules  /usr/local/lib/node_modules

# System deps + ESLint + Socket CLI (npm now available from node stage above)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl git wget ca-certificates libatomic1
RUN --mount=type=cache,target=/root/.npm \
    npm install -g eslint eslint-plugin-security \
      @typescript-eslint/parser @typescript-eslint/eslint-plugin socket

# Bandit + socketsecurity via uv
ENV UV_LINK_MODE=copy
RUN --mount=type=cache,target=/root/.cache/uv \
    uv tool install bandit && uv tool install socketsecurity
ENV PATH="/root/.local/bin:$PATH"

# App source
COPY src/socket_external_tools_runner.py /socket-security-tools/
COPY src/version.py                       /socket-security-tools/
COPY src/core                             /socket-security-tools/core
COPY entrypoint.sh                        /socket-security-tools/

RUN chmod +x /socket-security-tools/entrypoint.sh

COPY pyproject.toml uv.lock /scripts/
WORKDIR /scripts
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen && uv pip install light-s3-client

ENV PATH="/scripts/.venv/bin:/root/.opengrep/cli/latest:$PATH"

ENTRYPOINT ["/socket-security-tools/entrypoint.sh"]
