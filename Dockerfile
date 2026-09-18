# ─── Pinned build inputs ──────────────────────────────────────────────────────
# Two kinds of pin live in this file, and they look different because Dependabot
# can only read one of them.
#
# 1. Images are pinned as literal tags on the FROM lines below. Dependabot's
#    Dockerfile parser is a regex over FROM lines whose image and tag groups
#    both require literal characters (`[a-z\d]` / `[\w]`); it does no ARG
#    substitution, so `FROM image:${VERSION}` and `FROM ${IMAGE}` are matched
#    with no version and silently skipped. Carrying the version inline is the
#    only form it updates. To use a different tag locally, edit the FROM line.
#
# 2. Tools installed by a script or package manager have no FROM line for
#    Dependabot to read, so they keep an ARG pin and are bumped by hand. These
#    stay overridable: docker build --build-arg OPENGREP_VERSION=v1.30.0 .
ARG OPENGREP_VERSION=v1.30.0
ARG SOCKET_NPM_CLI_VERSION=1.1.176
#
# 3. Socket-built Trivy, rebuilt from unmodified upstream source and published
#    by Socket's own release pipeline. Deliberately kept out of Dependabot's
#    reach: it is pinned by digest and both ARGs move together with that
#    release process, never independently. Building requires pull access to the
#    registry; contributors without it can override, e.g.:
#    docker build --build-arg TRIVY_IMAGE=aquasec/trivy:0.73.0 .
#    TRIVY_VERSION feeds the image label — keep it in sync with the tag.
ARG TRIVY_VERSION=0.73.0
ARG TRIVY_IMAGE=ghcr.io/socketdev/trivy:0.73.0@sha256:e3d9d5f10250cb73b0ea9446ae1191c0f2da2f5e6173eac08a840b1812f02e0b

# ─── Stage: trivy (Socket-built redistribution) ───────────────────────────────
FROM ${TRIVY_IMAGE} AS trivy

# ─── Stage: trufflehog ────────────────────────────────────────────────────────
FROM trufflesecurity/trufflehog:3.97.5 AS trufflehog

# ─── Stage: uv ────────────────────────────────────────────────────────────────
# Named stage required — COPY --from does not support ARG variable expansion.
FROM ghcr.io/astral-sh/uv:0.12.17 AS uv

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

WORKDIR /socket-basics

COPY --from=uv /uv /uvx /bin/

# Binary tools from immutable build stages
COPY --from=trivy      /usr/local/bin/trivy       /usr/local/bin/trivy
COPY --from=trufflehog /usr/bin/trufflehog        /usr/local/bin/trufflehog
COPY --from=opengrep-installer /root/.opengrep    /root/.opengrep

# System deps + Node.js 22.x + Socket CLI
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      curl git wget ca-certificates
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs
ARG SOCKET_NPM_CLI_VERSION
RUN --mount=type=cache,target=/root/.npm \
    npm install -g "socket@${SOCKET_NPM_CLI_VERSION}"

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
ARG OPENGREP_VERSION
# Mirrors the trufflehog FROM tag above. A literal FROM tag cannot be read back
# into an ARG, so this is the one pin stated twice;
# tests/test_dockerfile_pins.py fails if the two ever disagree.
ARG TRUFFLEHOG_VERSION=3.97.5
ARG SOCKET_NPM_CLI_VERSION
LABEL org.opencontainers.image.title="Socket Basics" \
      org.opencontainers.image.source="https://github.com/SocketDev/socket-basics" \
      org.opencontainers.image.version="${SOCKET_BASICS_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      com.socket.trivy-version="${TRIVY_VERSION}" \
      com.socket.trufflehog-version="${TRUFFLEHOG_VERSION}" \
      com.socket.opengrep-version="${OPENGREP_VERSION}" \
      com.socket.npm-cli-version="${SOCKET_NPM_CLI_VERSION}"

ENV PATH="/socket-basics/.venv/bin:/root/.opengrep/cli/latest:/usr/local/bin:$PATH"

ENTRYPOINT ["socket-basics"]
