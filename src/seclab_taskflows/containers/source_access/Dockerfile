# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

FROM debian:trixie-slim AS tgrep
ARG TGREP_VERSION=1.0.4
ARG TGREP_SHA256_AMD64=81fd408f619fc1a316ed0618b2d2062b463631bdfd71123050580293817074fb
ARG TGREP_SHA256_ARM64=8df6ab6ab6d859c38df3c6ee39c39bab66165761371a46a325021dd3c25607fb
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
        amd64) target=x86_64; checksum="${TGREP_SHA256_AMD64}" ;; \
        arm64) target=aarch64; checksum="${TGREP_SHA256_ARM64}" ;; \
        *) echo "Unsupported tgrep architecture" >&2; exit 1 ;; \
    esac; \
    temp_dir="$(mktemp -d)"; \
    curl -fsSL --retry 3 \
        "https://github.com/microsoft/tgrep/releases/download/v${TGREP_VERSION}/tgrep-v${TGREP_VERSION}-${target}-unknown-linux-musl.tar.gz" \
        -o "${temp_dir}/tgrep.tar.gz"; \
    printf '%s  %s\n' "${checksum}" "${temp_dir}/tgrep.tar.gz" | sha256sum -c -; \
    tar -xzf "${temp_dir}/tgrep.tar.gz" -C "${temp_dir}"; \
    install -m 755 "${temp_dir}/tgrep" /usr/local/bin/tgrep; \
    rm -rf "${temp_dir}"

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils git ca-certificates file binutils xxd \
    universal-ctags global cscope fd-find tree \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tgrep /usr/local/bin/tgrep /usr/local/bin/tgrep
WORKDIR /workspace