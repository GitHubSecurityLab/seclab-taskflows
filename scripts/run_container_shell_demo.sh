#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Run container shell demo taskflows.
# Must be run from the root of the seclab-taskflows repository.
#
# Usage:
#   ./scripts/run_container_shell_demo.sh base    [workspace_dir]
#   ./scripts/run_container_shell_demo.sh malware [workspace_dir] [target_filename]
#   ./scripts/run_container_shell_demo.sh network [workspace_dir] [capture_filename]
#   ./scripts/run_container_shell_demo.sh sast    [workspace_dir] [target]
#
# If workspace_dir is omitted a temporary directory is used.
# Requires AI_API_TOKEN to be set in the environment.

set -euo pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__root="$(cd "${__dir}/.." && pwd)"

export PATH="${__root}/.venv/bin:${PATH}"

if [ -z "${AI_API_TOKEN:-}" ]; then
    echo "AI_API_TOKEN is not set" >&2
    exit 1
fi

demo="${1:-}"
if [ -z "$demo" ]; then
    echo "Usage: $0 <base|malware|network|sast> [workspace_dir] [target]" >&2
    exit 1
fi

workspace="${2:-$(mktemp -d)}"
mkdir -p "$workspace"

case "$demo" in
    base)
        target="${3:-hello}"
        if [ ! -f "${workspace}/${target}" ]; then
            echo "Copying /bin/ls to ${workspace}/${target} as demo target"
            cp /bin/ls "${workspace}/${target}"
        fi
        CONTAINER_WORKSPACE="$workspace" \
        LOG_DIR="${__root}/logs" \
        python -m seclab_taskflow_agent \
            -t seclab_taskflows.taskflows.container_shell.demo_base \
            -g target="$target"
        ;;
    malware)
        target="${3:-suspicious.elf}"
        if [ ! -f "${workspace}/${target}" ]; then
            echo "Copying /bin/ls to ${workspace}/${target} as demo target"
            cp /bin/ls "${workspace}/${target}"
        fi
        CONTAINER_WORKSPACE="$workspace" \
        LOG_DIR="${__root}/logs" \
        python -m seclab_taskflow_agent \
            -t seclab_taskflows.taskflows.container_shell.demo_malware_analysis \
            -g target="$target"
        ;;
    network)
        capture="${3:-sample.pcap}"
        if [ ! -f "${workspace}/${capture}" ]; then
            echo "No pcap found at ${workspace}/${capture}" >&2
            echo "Provide a pcap file or set workspace_dir to a directory containing one." >&2
            exit 1
        fi
        CONTAINER_WORKSPACE="$workspace" \
        LOG_DIR="${__root}/logs" \
        python -m seclab_taskflow_agent \
            -t seclab_taskflows.taskflows.container_shell.demo_network_analysis \
            -g capture="$capture"
        ;;
    sast)
        target="${3:-.}"
        if [ ! -d "$workspace" ] && [ ! -f "${workspace}/${target}" ]; then
            echo "No source found at ${workspace}/${target}" >&2
            echo "Provide a source directory or file in workspace_dir." >&2
            exit 1
        fi
        if [ "$target" = "." ] && [ -z "$(ls -A "$workspace" 2>/dev/null)" ]; then
            echo "Generating demo Python source in ${workspace}"
            cat > "${workspace}/demo.py" <<'PYEOF'
import os
import subprocess


def read_config(path):
    with open(path) as f:
        return f.read()


def run_command(cmd):
    # intentional anti-pattern for demo purposes
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def process_input(user_input):
    result = run_command(f"echo {user_input}")
    return result.stdout


def main():
    config = read_config("/etc/demo.conf") if os.path.exists("/etc/demo.conf") else ""
    output = process_input("hello world")
    print(config, output)


if __name__ == "__main__":
    main()
PYEOF
            target="demo.py"
        fi
        CONTAINER_WORKSPACE="$workspace" \
        LOG_DIR="${__root}/logs" \
        python -m seclab_taskflow_agent \
            -t seclab_taskflows.taskflows.container_shell.demo_sast \
            -g target="$target"
        ;;
    *)
        echo "Unknown demo: $demo. Choose base, malware, network, or sast." >&2
        exit 1
        ;;
esac
