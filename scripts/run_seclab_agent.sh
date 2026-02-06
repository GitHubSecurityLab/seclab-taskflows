#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# https://stackoverflow.com/a/53122736
__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

${__dir}/run_in_docker.sh python -m seclab_taskflow_agent "$@"
