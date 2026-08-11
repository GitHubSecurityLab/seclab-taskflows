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
    && case "$arch" in \
        amd64) sha256="6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971" ;; \
        arm64) sha256="16e5017863a7f6071363782b1b8042eb12c6ca4f4cd71528b2123f0a1275b13e" ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tar.gz \
    && echo "${sha256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
# A login shell re-reads /etc/profile and would drop the PATH set above, so
# make the toolchain reachable that way too.
RUN printf 'export PATH="/usr/local/go/bin:/root/go/bin:$PATH"\n' > /etc/profile.d/golang.sh

WORKDIR /workspace
