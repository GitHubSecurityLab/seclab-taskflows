# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Reproduction container for the audit v2 pipeline.
#
# This is the only image in which candidate exploits are actually executed. It
# carries the runtimes and debugging tools needed to stand a target up and
# trigger a finding, but it is meant to run with no network by default; the
# operator opts into egress explicitly when a target needs to fetch its own
# dependencies.

FROM ghcr.io/githubsecuritylab/seclab-shell-base:latest
# `ltrace` is deliberately absent: it has no arm64 package on bookworm, which
# would make this image build on CI but not on Apple Silicon. strace covers it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gdb valgrind strace \
    python3-venv python3-dev \
    nodejs npm \
    default-jre-headless \
    jq netcat-openbsd socat procps lsof psmisc \
    ripgrep tree less \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
