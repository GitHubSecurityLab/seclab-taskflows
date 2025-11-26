#!/bin/bash
# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

set -e

if [ -z "$1" ]; then 
  echo "Usage: $0 <repo>"; 
  exit 1; 
fi

./run_seclab_agent.sh -t seclab_taskflows.taskflows.audit.fetch_source_code -g repo=$1
./run_seclab_agent.sh -t seclab_taskflows.taskflows.audit.identify_applications -g repo=$1
./run_seclab_agent.sh -t seclab_taskflows.taskflows.audit.gather_web_entry_point_info -g repo=$1
./run_seclab_agent.sh -t seclab_taskflows.taskflows.audit.classify_application_local -g repo=$1
./run_seclab_agent.sh -t seclab_taskflows.taskflows.audit.audit_issue_local_iter -g repo=$1