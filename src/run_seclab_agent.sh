# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

if [ ! -f ".env" ]; then
    touch ".env"
fi

mkdir -p logs
mkdir -p data

docker run -i \
       --mount type=bind,src="$PWD",dst=/app \
       -e GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_PERSONAL_ACCESS_TOKEN" -e COPILOT_TOKEN="$COPILOT_TOKEN" "ghcr.io/githubsecuritylab/seclab-taskflow-agent" "$@"
