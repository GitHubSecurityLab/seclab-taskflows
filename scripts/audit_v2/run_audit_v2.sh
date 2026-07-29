#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Run the audit v2 pipeline against a repository.
#
# The five stages are separate taskflows rather than one file on purpose. Each
# one is expensive, and each ends at a durable checkpoint in the finding
# ledger, so a stage can be rerun on its own without redoing the ones before
# it. That is also why stage state lives in the ledger rather than in taskflow
# outputs: multi-model tasks do not feed a shared result channel, so the ledger
# is the only place the stages can meet.
#
# Usage: ./scripts/audit_v2/run_audit_v2.sh [options] <owner/repo>
#
# Options:
#   -m <model_config>   Override the model config each taskflow declares.
#                       Use seclab_taskflows.configs.model_config_audit_v2_lowercost
#                       for cheaper exploratory runs.
#   -s <stage>          Run a single stage: survey|hunt|contest|reproduce|report.
#                       Repeatable. Default: all five, in order.
#   --from <stage>      Run from this stage to the end, after fixing a stage
#                       that failed part way through.
#   --no-reproduce      Skip reproduction. Findings then top out at `confirmed`
#                       and the report says so.
#   -h, --help          Show this message.

set -euo pipefail

ALL_STAGES=(survey hunt contest reproduce report)
STAGES=()
FROM_STAGE=""
SKIP_REPRODUCE=false
MODEL_CONFIG_FLAG=()

usage() {
    sed -n '6,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 && "$1" == -* ]]; do
    case "$1" in
        -m)
            MODEL_CONFIG_FLAG=(-m "$2")
            shift 2
            ;;
        -s)
            STAGES+=("$2")
            shift 2
            ;;
        --from)
            FROM_STAGE="$2"
            shift 2
            ;;
        --no-reproduce)
            SKIP_REPRODUCE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

REPO="${1:-}"
if [ -z "$REPO" ]; then
    usage >&2
    exit 1
fi

if [ -n "$FROM_STAGE" ] && [ ${#STAGES[@]} -gt 0 ]; then
    echo "Use either --from or -s, not both." >&2
    exit 1
fi

if [ -n "$FROM_STAGE" ]; then
    seen=false
    for stage in "${ALL_STAGES[@]}"; do
        [ "$stage" = "$FROM_STAGE" ] && seen=true
        [ "$seen" = true ] && STAGES+=("$stage")
    done
    if [ "$seen" != true ]; then
        echo "Unknown stage: ${FROM_STAGE}" >&2
        exit 1
    fi
fi

if [ ${#STAGES[@]} -eq 0 ]; then
    STAGES=("${ALL_STAGES[@]}")
fi

for stage in "${STAGES[@]}"; do
    valid=false
    for known in "${ALL_STAGES[@]}"; do
        [ "$stage" = "$known" ] && valid=true
    done
    if [ "$valid" != true ]; then
        echo "Unknown stage: ${stage}" >&2
        exit 1
    fi
done

if [ "$SKIP_REPRODUCE" = true ]; then
    filtered=()
    for stage in "${STAGES[@]}"; do
        [ "$stage" = "reproduce" ] || filtered+=("$stage")
    done
    STAGES=(${filtered[@]+"${filtered[@]}"})
fi

if [ ${#STAGES[@]} -eq 0 ]; then
    echo "No stages left to run." >&2
    exit 1
fi

# Reproduction is the one stage that executes attacker-controlled input, so a
# missing image is worth catching now rather than halfway through a finding.
for stage in "${STAGES[@]}"; do
    if [ "$stage" = "reproduce" ] &&
        ! docker image inspect ghcr.io/githubsecuritylab/seclab-shell-reproduction:latest >/dev/null 2>&1; then
        echo "The reproduction image is missing. Build it with:" >&2
        echo "  ./scripts/build_container_images.sh reproduction" >&2
        exit 1
    fi
done

echo "audit v2: ${REPO}"
echo "stages:   ${STAGES[*]}"
echo

for stage in "${STAGES[@]}"; do
    echo "=== ${stage} ==="
    python -m seclab_taskflow_agent \
        ${MODEL_CONFIG_FLAG[@]+"${MODEL_CONFIG_FLAG[@]}"} \
        -t "seclab_taskflows.taskflows.audit_v2.${stage}" \
        -g repo="${REPO}"
    echo
done

echo "The findings are in the ledger. Re-read the report at any time with:"
echo "  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit_v2.report -g repo=${REPO}"
