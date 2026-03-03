#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT
#
# Local test / demo script for the PVR triage taskflows.
#
# Usage:
#   ./scripts/run_pvr_triage.sh batch          <owner/repo>
#   ./scripts/run_pvr_triage.sh triage         <owner/repo> <GHSA-xxxx-xxxx-xxxx>
#   ./scripts/run_pvr_triage.sh respond        <owner/repo> <GHSA-xxxx-xxxx-xxxx> <comment|reject|withdraw>
#   ./scripts/run_pvr_triage.sh respond_batch  <owner/repo> <comment|reject|withdraw>
#   ./scripts/run_pvr_triage.sh demo           <owner/repo>
#
# Environment (any already-set values are respected):
#   GH_TOKEN        — GitHub token; falls back to: gh auth token
#   AI_API_TOKEN    — AI API key (required, must be set before running)
#   AI_API_ENDPOINT — defaults to https://api.githubcopilot.com
#   REPORT_DIR      — defaults to ./reports
#   LOG_DIR         — defaults to ./logs

set -euo pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__root="$(cd "${__dir}/.." && pwd)"

# ---------------------------------------------------------------------------
# Usage (defined early so --help can fire before env validation)
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [args]

Commands:
  batch          <owner/repo>
      Score unprocessed draft advisories and save a ranked queue table to REPORT_DIR.
      Advisories already present in REPORT_DIR are skipped.

  triage         <owner/repo> <GHSA-xxxx-xxxx-xxxx>
      Run full triage on one advisory: verify code, generate report + response draft.

  respond        <owner/repo> <GHSA-xxxx-xxxx-xxxx> <action>
      Post the response draft to GitHub. action = comment | reject | withdraw
      Requires pvr_triage to have been run first for the given GHSA.

  respond_batch  <owner/repo> <action>
      Scan REPORT_DIR for all pending response drafts and post them in one session.
      action = comment | reject | withdraw

  demo           <owner/repo>
      Full pipeline on the given repo (batch → triage on first draft advisory → report preview).
      Does not post anything to GitHub.

Environment:
  GH_TOKEN        — GitHub token; falls back to: gh auth token
  AI_API_TOKEN    — AI API key (required, must be set before running)
  AI_API_ENDPOINT — defaults to https://api.githubcopilot.com
  REPORT_DIR      — defaults to ./reports
  LOG_DIR         — defaults to ./logs
EOF
}

case "${1:-}" in
    -h|--help|help|"") usage; exit 0 ;;
esac

# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

# Prepend local venv to PATH if present (resolves 'python' for MCP servers)
if [ -d "${__root}/.venv/bin" ]; then
    export PATH="${__root}/.venv/bin:${PATH}"
fi

# GitHub token
if [ -z "${GH_TOKEN:-}" ]; then
    if command -v gh &>/dev/null; then
        GH_TOKEN="$(gh auth token 2>/dev/null)" || true
    fi
    if [ -z "${GH_TOKEN:-}" ]; then
        echo "ERROR: GH_TOKEN not set and 'gh auth token' failed." >&2
        exit 1
    fi
    export GH_TOKEN
fi

# AI API token
if [ -z "${AI_API_TOKEN:-}" ]; then
    echo "ERROR: AI_API_TOKEN is not set." >&2
    exit 1
fi

export AI_API_ENDPOINT="${AI_API_ENDPOINT:-https://api.githubcopilot.com}"

export REPORT_DIR="${REPORT_DIR:-${__root}/reports}"
mkdir -p "${REPORT_DIR}"

export LOG_DIR="${LOG_DIR:-${__root}/logs}"
mkdir -p "${LOG_DIR}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

run_agent() {
    python -m seclab_taskflow_agent "$@"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_batch() {
    local repo="${1:?Usage: $0 batch <owner/repo>}"
    echo "==> Scoring inbox for ${repo} ..."
    run_agent \
        -t seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch \
        -g "repo=${repo}"
}

cmd_triage() {
    local repo="${1:?Usage: $0 triage <owner/repo> <GHSA>}"
    local ghsa="${2:?Usage: $0 triage <owner/repo> <GHSA>}"
    echo "==> Triaging ${ghsa} in ${repo} ..."
    run_agent \
        -t seclab_taskflows.taskflows.pvr_triage.pvr_triage \
        -g "repo=${repo}" \
        -g "ghsa=${ghsa}"
}

cmd_respond() {
    local repo="${1:?Usage: $0 respond <owner/repo> <GHSA> <action>}"
    local ghsa="${2:?Usage: $0 respond <owner/repo> <GHSA> <action>}"
    local action="${3:?Usage: $0 respond <owner/repo> <GHSA> <action>}"
    case "${action}" in
        comment|reject|withdraw) ;;
        *) echo "ERROR: action must be comment, reject, or withdraw" >&2; exit 1 ;;
    esac
    echo "==> Responding to ${ghsa} in ${repo} (action=${action}) ..."
    run_agent \
        -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
        -g "repo=${repo}" \
        -g "ghsa=${ghsa}" \
        -g "action=${action}"
}

cmd_respond_batch() {
    local repo="${1:?Usage: $0 respond_batch <owner/repo> <action>}"
    local action="${2:?Usage: $0 respond_batch <owner/repo> <action>}"
    case "${action}" in
        comment|reject|withdraw) ;;
        *) echo "ERROR: action must be comment, reject, or withdraw" >&2; exit 1 ;;
    esac
    echo "==> Bulk respond for ${repo} (action=${action}) ..."
    run_agent \
        -t seclab_taskflows.taskflows.pvr_triage.pvr_respond_batch \
        -g "repo=${repo}" \
        -g "action=${action}"
}

cmd_demo() {
    local repo="${1:?Usage: $0 demo <owner/repo>}"

    # Pick the first draft advisory, or bail if none
    local ghsa
    ghsa="$(gh api "/repos/${repo}/security-advisories?state=draft&per_page=1" \
        --jq '.[0].ghsa_id // empty' 2>/dev/null)" || true

    if [ -z "${ghsa}" ]; then
        echo "No draft advisories found in ${repo}. Create one at:" >&2
        echo "  https://github.com/${repo}/security/advisories/new" >&2
        exit 1
    fi

    echo "==> Demo: ${repo}  advisory: ${ghsa}"
    echo

    echo "--- Step 1: batch inbox score ---"
    cmd_batch "${repo}"
    echo

    echo "--- Step 2: full triage ---"
    cmd_triage "${repo}" "${ghsa}"
    echo

    echo "--- Reports written to ${REPORT_DIR} ---"
    ls -1 "${REPORT_DIR}"/*.md 2>/dev/null || true
    echo
    echo "To post the response draft (comment only, does not reject):"
    echo "  $0 respond ${repo} ${ghsa} comment"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

case "${1:-}" in
    batch)          shift; cmd_batch          "$@" ;;
    triage)         shift; cmd_triage         "$@" ;;
    respond)        shift; cmd_respond        "$@" ;;
    respond_batch)  shift; cmd_respond_batch  "$@" ;;
    demo)           shift; cmd_demo           "$@" ;;
    *) echo "ERROR: unknown command '${1}'" >&2; usage; exit 1 ;;
esac
