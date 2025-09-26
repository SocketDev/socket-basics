# Use the official Python image as a base
FROM python:3.12

# Create application directory
WORKDIR /socket-security-tools
ENV PATH=$PATH:/usr/local/go/bin

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3

# Install Trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin


RUN apt-get update && apt-get install -y curl git wget

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3

# Install Trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install OpenGrep (connector/runtime dependency)
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Copy socket_basics package so we can install the CLI entrypoint
COPY socket_basics /socket-security-tools/socket_basics
# Also copy the project root so editable install has access to all files
COPY . /socket-security-tools/

COPY pyproject.toml uv.lock LICENSE README.md /scripts/
# Install Python dependencies using uv
WORKDIR /scripts
RUN uv sync --frozen && uv pip install light-s3-client
ENV PATH="/scripts/.venv/bin:/root/.opengrep/cli/latest:$PATH"

# Install this package so the `socket-basics` CLI entrypoint is available
WORKDIR /socket-security-tools
# Ensure python can import package if install doesn't run; prefer installed package
ENV PYTHONPATH="/socket-security-tools:${PYTHONPATH}"
# Ensure pyproject is present for editable install; fail loudly if install fails
RUN uv pip install -e . || pip install -e .

# Use socket-basics as the default entrypoint
ENTRYPOINT ["socket-basics"]
