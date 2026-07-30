# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils python3 python3-pip curl wget git ca-certificates \
    file binutils xxd \
    && rm -rf /var/lib/apt/lists/*

# Debian bookworm ships Go 1.19, which refuses to build any module declaring a
# newer toolchain, so take Go from upstream. dpkg's architecture names match
# Go's release naming for amd64 and arm64.
ARG GO_VERSION=1.23.4
RUN arch="$(dpkg --print-architecture)" \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
# A login shell re-reads /etc/profile and would drop the PATH set above, so
# make the toolchain reachable that way too.
RUN printf 'export PATH="/usr/local/go/bin:/root/go/bin:$PATH"\n' > /etc/profile.d/golang.sh

WORKDIR /workspace
