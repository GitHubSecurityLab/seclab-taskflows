#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# https://stackoverflow.com/a/53122736
__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

${__dir}/../run_in_docker.sh ${__dir}/run_audit.sh "$1"
