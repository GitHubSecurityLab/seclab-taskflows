#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT
#
# install_afl.sh — install AFL++ (latest release tag) and llvm/lcov tooling
# required by the fuzzing taskflow. Idempotent: if afl-clang-lto and llvm-cov
# are already on PATH, this script is a no-op.

set -euo pipefail

AFL_REPO="https://github.com/AFLplusplus/AFLplusplus.git"
AFL_PREFIX="${AFL_PREFIX:-$HOME/.local/opt/AFLplusplus}"
APT_PACKAGES=(
  build-essential clang llvm llvm-dev lld
  libclang-rt-dev
  python3-dev automake cmake git ninja-build
  pkg-config bison flex libgtk-3-dev gnuplot-nox
  gcc-multilib
  lcov gcovr
  # Used by fuzz_runner.build_call_graph (E3) and the SAST container
  universal-ctags cscope graphviz
)

log() { printf '[install_afl] %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

ensure_apt_packages() {
  local missing=()
  for pkg in "${APT_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [ ${#missing[@]} -eq 0 ]; then
    log "apt prerequisites already satisfied"
    return 0
  fi
  log "installing apt prerequisites: ${missing[*]}"
  if [ "$(id -u)" -eq 0 ]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  elif have sudo; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  else
    log "ERROR: missing packages and no sudo available: ${missing[*]}"
    return 1
  fi
}

latest_release_tag() {
  # Pick the highest semver-looking tag (e.g. v4.32c, 4.32c) from upstream.
  git -c versionsort.suffix=- ls-remote --tags --refs --sort=-v:refname "$AFL_REPO" \
    | awk -F/ '{print $NF}' \
    | grep -E '^v?[0-9]+(\.[0-9]+)+[a-z]?$' \
    | head -1
}

install_afl() {
  if have afl-clang-lto && have afl-fuzz; then
    log "AFL++ already installed: $(afl-fuzz -V 2>&1 | head -1)"
    return 0
  fi
  local tag
  tag="$(latest_release_tag)"
  if [ -z "$tag" ]; then
    log "ERROR: could not resolve latest AFL++ release tag"
    return 1
  fi
  log "building AFL++ tag $tag into $AFL_PREFIX"
  local src="${AFL_PREFIX}-src"
  rm -rf "$src"
  git clone --depth 1 --branch "$tag" "$AFL_REPO" "$src"
  (
    cd "$src"
    # source build covers afl-clang-lto, afl-clang-fast, afl-fuzz, afl-cov tooling, etc.
    make distrib PREFIX="$AFL_PREFIX" -j"$(nproc)"
    make install PREFIX="$AFL_PREFIX"
  )
  rm -rf "$src"
  # Persist PATH for future shells (idempotent).
  local rc="$HOME/.bashrc"
  local line="export PATH=\"$AFL_PREFIX/bin:\$PATH\"  # added by install_afl.sh"
  if [ -f "$rc" ] && ! grep -qF "$line" "$rc"; then
    printf '\n%s\n' "$line" >> "$rc"
  fi
  export PATH="$AFL_PREFIX/bin:$PATH"
  log "AFL++ installed: $(afl-fuzz -V 2>&1 | head -1)"
}

ensure_llvm_cov() {
  if have llvm-cov && have llvm-profdata; then
    log "llvm-cov / llvm-profdata present: $(llvm-cov --version | head -1)"
    return 0
  fi
  log "WARNING: llvm-cov / llvm-profdata not found. Coverage feedback will fall back to gcov."
}

main() {
  ensure_apt_packages
  install_afl
  ensure_llvm_cov
  log "done"
}

main "$@"
