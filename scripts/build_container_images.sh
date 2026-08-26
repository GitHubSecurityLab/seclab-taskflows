#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Build seclab container shell images.
# Must be run from the root of the seclab-taskflows repository.
# Images must be rebuilt whenever a Dockerfile changes.
#
# Usage: ./scripts/build_container_images.sh [base|malware|network|source-access|sast|all]
#   default: all
#
# Environment:
#   PUSH        set to 1 to also push the images to the registry
#   IMAGE_TAGS  space-separated tags to apply (default: latest)
#   BASE_IMAGE  base image the derived images build on
#               (default: ${IMAGE_PREFIX}/seclab-shell-base:latest)

set -euo pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__root="$(cd "${__dir}/.." && pwd)"
CONTAINERS_DIR="${__root}/src/seclab_taskflows/containers"
IMAGE_PREFIX="ghcr.io/githubsecuritylab"

PUSH="${PUSH:-0}"
IMAGE_TAGS="${IMAGE_TAGS:-latest}"
BASE_IMAGE="${BASE_IMAGE:-${IMAGE_PREFIX}/seclab-shell-base:latest}"

read -ra IMAGE_TAG_LIST <<< "${IMAGE_TAGS}"

# build_image <image-name> <context-subdir> [extra docker buildx build args...]
build_image() {
    local name="$1" context="$2"
    shift 2
    local image="${IMAGE_PREFIX}/${name}"
    local args=()
    local tag
    for tag in "${IMAGE_TAG_LIST[@]}"; do
        args+=(--tag "${image}:${tag}")
    done
    if [[ "${PUSH}" == "1" ]]; then
        args+=(--push)
    fi
    echo "Building ${image}..."
    docker buildx build "${args[@]}" "$@" "${CONTAINERS_DIR}/${context}/"
}

build_base() {
    build_image seclab-shell-base base
}

build_malware() {
    build_image seclab-shell-malware-analysis malware_analysis --build-arg "BASE_IMAGE=${BASE_IMAGE}"
}

build_network() {
    build_image seclab-shell-network-analysis network_analysis --build-arg "BASE_IMAGE=${BASE_IMAGE}"
}

build_source_access() {
    build_image seclab-shell-source-access source_access
}

build_sast() {
    build_image seclab-shell-sast sast --build-arg "BASE_IMAGE=${BASE_IMAGE}"
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
    source-access)
        build_source_access
        ;;
    sast)
        build_base
        build_sast
        ;;
    all)
        build_base
        build_malware
        build_network
        build_source_access
        build_sast
        ;;
    *)
        echo "Unknown target: $target" >&2
        echo "Usage: $0 [base|malware|network|source-access|sast|all]" >&2
        exit 1
        ;;
esac

echo "Done."
