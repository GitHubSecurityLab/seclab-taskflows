# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

ARG BASE_IMAGE=ghcr.io/githubsecuritylab/seclab-shell-base:latest
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap tcpdump tshark netcat-openbsd dnsutils curl jq httpie \
    && rm -rf /var/lib/apt/lists/*
