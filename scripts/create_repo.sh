#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Script for creating a new taskflows repo.
# Usage:
#
#  cd <empty directory>
#  python -m venv venv
#  source venv/bin/activate
#  pip install hatch
#  git clone https://github.com/GitHubSecurityLab/seclab-taskflows.git
#  ./seclab-taskflows/scripts/create_repo.sh "My Project"
#
# The script creates a sub-directory named "new-taskflows-repo",
# containing a new git repo with an initial commit. It contains
# the basic directory structure that you need to start your own
# taskflow project.

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <Project Name>";
  exit 1;
fi

# Get location of seclab-taskflows repo. (Use the location of this
# script, which is in that repo.)
SECLAB_TASKFLOWS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"

hatch new "$1" new-taskflows-repo
cd new-taskflows-repo

# Copy files from seclab-taskflows repo.
cp -r "$SECLAB_TASKFLOWS/.devcontainer" .
cp "$SECLAB_TASKFLOWS/CODE_OF_CONDUCT.md" .
cp "$SECLAB_TASKFLOWS/.gitignore" .
cp "$SECLAB_TASKFLOWS/.github/workflows/publish-to-pypi.yaml" .github/workflows/
cp "$SECLAB_TASKFLOWS/.github/workflows/publish-to-testpypi.yaml" .github/workflows/

# Replace any occurrences of "seclab-taskflows" with the correct project name.
PROJECT_NAME="$(hatch project metadata name)"
find . -type f -exec sed -i "s/seclab-taskflows/$PROJECT_NAME/g" {} \;

# Get the path to the source code. (Usually something like "src/my_project")
SRCDIR="$(dirname $(find . -name __about__.py))"

# Create directories
mkdir "$SRCDIR/configs"
echo "# Configs" > "$SRCDIR/configs/README.md"
mkdir "$SRCDIR/mcp_servers"
echo "# MCP servers" > "$SRCDIR/mcp_servers/README.md"
mkdir "$SRCDIR/personalities"
echo "# Personalities" > "$SRCDIR/personalities/README.md"
mkdir "$SRCDIR/prompts"
echo "# Prompts" > "$SRCDIR/prompts/README.md"
mkdir "$SRCDIR/taskflows"
echo "# Taskflows" > "$SRCDIR/taskflows/README.md"
mkdir "$SRCDIR/toolboxes"
echo "# Toolboxes" > "$SRCDIR/toolboxes/README.md"

# Add dependency on seclab-taskflows
uv add seclab-taskflow-agent --active --frozen

# Create initial git commit.
git init
git add .
git commit -m "Initial commit"
