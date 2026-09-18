# ─── Pinned build inputs ──────────────────────────────────────────────────────
# Images are pinned as literal tags on the FROM lines below, which is the only
# form Dependabot's Dockerfile parser reads — it does no ARG substitution, so
# `FROM image:${VERSION}` is silently skipped. See the note at the top of the
# root ./Dockerfile.
#
# Tools installed by a script or package manager have no FROM line, so they keep
# an ARG pin and are bumped by hand. Overridable at build time, e.g.:
#   docker build --build-arg OPENGREP_VERSION=v1.33.1 -f app_tests/Dockerfile app_tests
ARG GOSEC_VERSION=v2.30.0
ARG OPENGREP_VERSION=v1.33.1
ARG SOCKET_NPM_CLI_VERSION=1.13.1
ARG SOCKET_PYTHON_CLI_VERSION=2.11.11
#
# Socket-built Trivy, pinned by digest and deliberately kept out of Dependabot's
# reach; updated by Socket's trivy-dist release process. See the root
# ./Dockerfile.
ARG TRIVY_IMAGE=ghcr.io/socketdev/trivy:0.76.1@sha256:883da3593a60e311b2ed87c3a55241051b27bba15ffc3ce041ae570cd0f00915

# ─── Stage: trivy (Socket-built redistribution) ───────────────────────────────
FROM ${TRIVY_IMAGE} AS trivy

# ─── Stage: trufflehog ────────────────────────────────────────────────────────
FROM trufflesecurity/trufflehog:3.99.8 AS trufflehog

# ─── Stage: golang ────────────────────────────────────────────────────────────
FROM golang:1.27.3 AS golang

# ─── Stage: node ──────────────────────────────────────────────────────────────
# Named stage replaces the nodesource curl install, which put the Node version
# out of reach of both Dependabot and the pin checkers.
FROM node:22-slim AS node

# ─── Stage: uv ────────────────────────────────────────────────────────────────
# Named stage required — COPY --from does not support ARG variable expansion.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

# ─── Stage: gosec-installer ───────────────────────────────────────────────────
FROM python:3.12-slim AS gosec-installer
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
FROM python:3.12-slim AS opengrep-installer
ARG OPENGREP_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates bash
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh \
    | bash -s -- -v "${OPENGREP_VERSION}"

# ─── Stage: runtime ───────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app-tests
ENV PATH=$PATH:/usr/local/go/bin

COPY --from=uv /uv /uvx /bin/

# Binary tools from immutable build stages
COPY --from=trivy           /usr/local/bin/trivy      /usr/local/bin/trivy
COPY --from=trufflehog      /usr/bin/trufflehog        /usr/local/bin/trufflehog
COPY --from=opengrep-installer /root/.opengrep         /root/.opengrep
COPY --from=golang          /usr/local/go              /usr/local/go
COPY --from=gosec-installer /usr/local/bin/gosec       /usr/local/bin/gosec

# Node binary + npm from the versioned node stage.
# npm/npx in the node image are symlinks into node_modules/npm/bin — COPY
# dereferences symlinks into flat files, which breaks npm's relative requires,
# so recreate them as proper symlinks instead of copying.
COPY --from=node /usr/local/bin/node          /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules  /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# System deps + ESLint + Socket CLI (npm now available from node stage above)
ARG SOCKET_NPM_CLI_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl git wget ca-certificates libatomic1 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1
# pip checks certificates against its own vendored CA bundle, not the system
# store, and the base image's pip trusts the compromised intermediates. 26.2.2
# vendors certifi 2026.10.19. Upgrade it against the system store fixed above.
RUN python -m pip install --no-cache-dir --cert /etc/ssl/certs/ca-certificates.crt --upgrade "pip>=26.2.2" \
    && python -c 'import sys, pip; sys.exit(tuple(map(int, pip.__version__.split(".")[:3])) < (26, 2, 2))'
RUN --mount=type=cache,target=/root/.npm \
    npm install -g eslint eslint-plugin-security \
      @typescript-eslint/parser @typescript-eslint/eslint-plugin \
      "socket@${SOCKET_NPM_CLI_VERSION}"

# Bandit + socketsecurity via uv
ENV UV_LINK_MODE=copy
ARG SOCKET_PYTHON_CLI_VERSION
# --refresh-package: this install pins an exact version, so a stale cached index
# response makes a freshly published release look like it does not exist ("no
# version of socketsecurity==X"). Refresh metadata for this one package rather
# than passing --no-cache, which would discard the cache mount's benefit for
# bandit and for already-built wheels.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv tool install bandit \
    && uv tool install --refresh-package socketsecurity \
        "socketsecurity==${SOCKET_PYTHON_CLI_VERSION}"
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
