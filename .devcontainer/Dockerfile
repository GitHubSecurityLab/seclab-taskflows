# Use Ubuntu 24.04 as base image to match the current environment
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Install system dependencies
# Note: Python and Git are installed via devcontainer features
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install CodeQL CLI
RUN curl -Ls -o /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
    && unzip /tmp/codeql.zip -d /opt \
    && mv /opt/codeql /opt/codeql-cli \
    && ln -s /opt/codeql-cli/codeql /usr/local/bin/codeql \
    && rm /tmp/codeql.zip

# Set working directory
WORKDIR /workspaces/seclab-taskflows

# The rest of the setup will be done in post-create script
