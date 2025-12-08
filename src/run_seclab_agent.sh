# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

if [ ! -f ".env" ]; then
    touch ".env"
fi

mkdir -p logs
mkdir -p data

docker run -i \
       --mount type=bind,src="$PWD",dst=/app \
       -e GH_TOKEN="$GH_TOKEN" -e AI_API_TOKEN="$AI_API_TOKEN" "ghcr.io/githubsecuritylab/seclab-taskflow-agent" "$@"
