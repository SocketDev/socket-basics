# Use the official Python image as a base
FROM python:3.12

# Create application directory
WORKDIR /socket-basics
ENV PATH=$PATH:/usr/local/go/bin

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install system dependencies
RUN apt-get update && apt-get install -y curl git wget

# Install Node.js 22.x
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs

# Install Socket CLI globally
RUN npm install -g socket

# Install Trivy
ARG TRIVY_VERSION=v0.67.2
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}"

# Install Trufflehog
ARG TRUFFLEHOG_VERSION=v3.93.3
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin "${TRUFFLEHOG_VERSION}"

# Install OpenGrep (connector/runtime dependency)
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Copy the specific files needed for the project
COPY socket_basics /socket-basics/socket_basics
COPY pyproject.toml /socket-basics/pyproject.toml
COPY README.md /socket-basics/README.md
COPY LICENSE /socket-basics/LICENSE
COPY uv.lock /socket-basics/uv.lock

# Install Python dependencies using uv from the project root
WORKDIR /socket-basics
RUN pip install -e . && uv sync --frozen --no-dev
ENV PATH="/socket-basics/.venv/bin:/root/.opengrep/cli/latest:/usr/bin:$PATH"

# Use socket-basics as the default entrypoint
ENTRYPOINT ["socket-basics"]
