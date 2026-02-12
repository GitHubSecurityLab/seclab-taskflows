#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

set -e

USE_ADVISORY=false

# Parse flags
while [[ "$1" == --* ]]; do
  case "$1" in
    --advisory)
      USE_ADVISORY=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$1" ]; then 
  echo "Usage: $0 [--advisory] <repo>"; 
  exit 1; 
fi

python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.fetch_source_code -g repo="$1"
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.identify_applications -g repo="$1"
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.gather_web_entry_point_info -g repo="$1"

if [ "$USE_ADVISORY" = true ]; then
  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.fetch_security_advisories -g repo="$1"
fi

python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.classify_application_local -g repo="$1"
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.audit_issue_local_iter -g repo="$1"

set +e

# If in codespaces, open the results database.
if [ -v CODESPACES ]; then
  RESULTS_DB=~/.local/share/seclab-taskflow-agent/seclab-taskflows/repo_context/repo_context.db
  if [ -f "$RESULTS_DB" ]; then
    if command -v code >/dev/null 2>&1; then
      code "$RESULTS_DB"
    fi
  fi
fi
