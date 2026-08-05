# ─── Global version pins (single source of truth) ────────────────────────────
# Dependabot tracks all ARGs below via the FROM lines that reference them.
# To override at build time: docker build --build-arg TRUFFLEHOG_VERSION=3.93.8 .
#
# Dependabot-trackable (each has a corresponding FROM <image>:<ARG> stage):
ARG GOLANG_VERSION=1.26.5
ARG NODE_VERSION=22
ARG PYTHON_VERSION=3.12
ARG TRUFFLEHOG_VERSION=3.96.0
ARG UV_VERSION=0.12.1
#
# NOT Dependabot-trackable (no official Docker image with a stable binary path):
ARG GOSEC_VERSION=v2.28.0
ARG OPENGREP_VERSION=v1.26.0
#
# NOT Dependabot-trackable — Socket-built Trivy, pinned by digest; updated by
# Socket's trivy-dist release process. See the note in the root ./Dockerfile.
ARG TRIVY_IMAGE=ghcr.io/socketdev/trivy:0.73.0@sha256:e3d9d5f10250cb73b0ea9446ae1191c0f2da2f5e6173eac08a840b1812f02e0b

# ─── Stage: trivy (Socket-built redistribution) ───────────────────────────────
FROM ${TRIVY_IMAGE} AS trivy

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

WORKDIR /app-tests
ENV PATH=$PATH:/usr/local/go/bin

COPY --from=uv /uv /uvx /bin/

# Binary tools from immutable build stages
COPY --from=trivy           /usr/local/bin/trivy      /usr/local/bin/trivy
COPY --from=trufflehog      /usr/bin/trufflehog        /usr/local/bin/trufflehog
COPY --from=opengrep-installer /root/.opengrep         /root/.opengrep
COPY --from=golang          /usr/local/go              /usr/local/go
COPY --from=gosec-installer /usr/local/bin/gosec       /usr/local/bin/gosec

# Node binary + npm from the versioned node stage (Dependabot-trackable).
# npm/npx in the node image are symlinks into node_modules/npm/bin — COPY
# dereferences symlinks into flat files, which breaks npm's relative requires,
# so recreate them as proper symlinks instead of copying.
COPY --from=node /usr/local/bin/node          /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules  /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

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

# NOTE: the legacy socket-security-tools runner (src/, entrypoint.sh) predates
# the socket_basics layout migration and no longer exists in this repo — the
# stale COPY/ENTRYPOINT lines had made this image unbuildable. Until the
# app-tests harness is modernized, this is a tools image (scanners + language
# runtimes) exercised by CI smoke checks against the fixture apps here.
# Build with app_tests/ as the context:
#   docker build -f app_tests/Dockerfile app_tests

ENV PATH="/root/.opengrep/cli/latest:$PATH"

CMD ["/bin/sh"]
