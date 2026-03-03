#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Build seclab container shell images.
# Must be run from the root of the seclab-taskflows repository.
# Images must be rebuilt whenever a Dockerfile changes.
#
# Usage: ./scripts/build_container_images.sh [base|malware|network|all]
#   default: all

set -euo pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__root="$(cd "${__dir}/.." && pwd)"
CONTAINERS_DIR="${__root}/src/seclab_taskflows/containers"

build_base() {
    echo "Building seclab-shell-base..."
    docker build -t seclab-shell-base:latest "${CONTAINERS_DIR}/base/"
}

build_malware() {
    echo "Building seclab-shell-malware-analysis..."
    docker build -t seclab-shell-malware-analysis:latest "${CONTAINERS_DIR}/malware_analysis/"
}

build_network() {
    echo "Building seclab-shell-network-analysis..."
    docker build -t seclab-shell-network-analysis:latest "${CONTAINERS_DIR}/network_analysis/"
}

build_sast() {
    echo "Building seclab-shell-sast..."
    docker build -t seclab-shell-sast:latest "${CONTAINERS_DIR}/sast/"
}

target="${1:-all}"

case "$target" in
    base)
        build_base
        ;;
    malware)
        build_base
        build_malware
        ;;
    network)
        build_base
        build_network
        ;;
    sast)
        build_base
        build_sast
        ;;
    all)
        build_base
        build_malware
        build_network
        build_sast
        ;;
    *)
        echo "Unknown target: $target" >&2
        echo "Usage: $0 [base|malware|network|sast|all]" >&2
        exit 1
        ;;
esac

echo "Done."
