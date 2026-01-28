#!/bin/bash
# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

if [ ! -f ".env" ]; then
    touch ".env"
fi

mkdir -p .local
mkdir -p logs
mkdir -p data

# Note: this uses the trick described [here](https://unix.stackexchange.com/a/646335)
# to pass extra command line arguments into `bash -c`.
docker run -i \
       --mount type=bind,src="$PWD",dst=/app \
       --mount type=bind,src="$PWD/.local",dst=/root/.local \
       -e GH_TOKEN="$GH_TOKEN" -e AI_API_TOKEN="$AI_API_TOKEN" --entrypoint /bin/bash \
       "ghcr.io/githubsecuritylab/seclab-taskflow-agent" \
       -c 'pip install -q -e /app && exec "$@"' this-is-bash-dollar-zero "$@"
