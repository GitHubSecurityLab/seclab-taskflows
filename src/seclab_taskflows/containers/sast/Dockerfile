# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

ARG BASE_IMAGE=ghcr.io/githubsecuritylab/seclab-shell-base:latest
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    universal-ctags global cscope ripgrep fd-find graphviz tree \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages semgrep pyan3
