#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT
#
# run_fuzzing.sh — autonomous fuzzing taskflow driver.
#
# Usage:
#   ./scripts/fuzzing/run_fuzzing.sh <owner/repo>
#
# Behaviour:
#   1. Installs AFL++ + llvm/clang/lcov on the host (no-op if already present).
#   2. Fetches the source code (reuses the audit fetch_source_code taskflow).
#   3. Identifies fuzz targets, analyses the build system, writes initial
#      harnesses, builds them.
#   4. Runs the fuzz / coverage / improve loop with geometric time budgets
#      (30s, 60s, 120s, 240s, 480s, 960s — ~32 min per target). Stops early
#      when coverage plateaus.
#   5. Triages crashes and writes a markdown report.
#
# Security note: AFL++ runs ON THE HOST (not in a container). Run this only
# in a disposable environment (Codespace, throwaway VM). Each shell command
# the agent issues to local_shell requires user confirmation by default.

set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <owner/repo>" >&2
  exit 1
fi
REPO="$1"

# Geometric schedule: each iteration doubles the previous budget.
SCHEDULE=(30 60 120 240 480 960)
PLATEAU_THRESHOLD_PCT="${FUZZ_PLATEAU_THRESHOLD_PCT:-1.0}"

# G3: how many candidate harnesses per target. Default 1 (no qualifier
# competition). Set to 2 or 3 for OSS-Fuzz-Gen-style multi-candidate
# generation; the qualifier stage will keep the best by 60s coverage.
HARNESS_CANDIDATES="${HARNESS_CANDIDATES:-1}"
QUALIFIER_SECONDS="${QUALIFIER_SECONDS:-60}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DASHBOARD_PORT="${FUZZ_DASHBOARD_PORT:-8765}"
DASHBOARD_PID=""

start_dashboard() {
  if [ "${FUZZ_NO_DASHBOARD:-0}" = "1" ]; then
    echo "[run_fuzzing] dashboard disabled (FUZZ_NO_DASHBOARD=1)"
    return
  fi
  # If something is already listening on the port, leave it alone.
  if (echo > "/dev/tcp/127.0.0.1/$DASHBOARD_PORT") 2>/dev/null; then
    echo "[run_fuzzing] dashboard already running on http://127.0.0.1:$DASHBOARD_PORT"
    return
  fi
  echo "[run_fuzzing] starting dashboard on http://127.0.0.1:$DASHBOARD_PORT"
  nohup python "$SCRIPT_DIR/dashboard.py" --port "$DASHBOARD_PORT" \
    > /tmp/fuzz_dashboard.log 2>&1 &
  DASHBOARD_PID=$!
  # Give it a moment to bind.
  sleep 1
  if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    echo "[run_fuzzing] WARNING: dashboard failed to start; see /tmp/fuzz_dashboard.log"
    DASHBOARD_PID=""
  fi
}

stop_dashboard() {
  if [ -n "$DASHBOARD_PID" ] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    echo "[run_fuzzing] stopping dashboard (pid $DASHBOARD_PID)"
    kill "$DASHBOARD_PID" 2>/dev/null || true
  fi
}
trap stop_dashboard EXIT INT TERM

run_taskflow() {
  local tf="$1"; shift
  python -m seclab_taskflow_agent -t "$tf" -g "repo=$REPO" "$@"
}

# Helper: query fuzz_context to detect coverage plateau across all harnesses
# for the repo. Returns 0 (= plateau) when at least one harness has 3+ runs and
# all harnesses with 3+ runs report a plateau.
plateau_reached() {
  python - <<PY
import sys
from seclab_taskflows.mcp_servers.fuzz_context import _coverage_summary, _ENGINE
from seclab_taskflows.mcp_servers.fuzz_context_models import Harness
from sqlalchemy.orm import Session

repo = "$REPO".lower()
threshold = float("$PLATEAU_THRESHOLD_PCT")

with Session(_ENGINE) as session:
    harnesses = session.query(Harness).filter_by(repo=repo).all()

if not harnesses:
    sys.exit(1)  # no harnesses → not a plateau, just nothing built yet

any_eligible = False
for h in harnesses:
    summary = _coverage_summary(h.id)
    if len(summary) < 3:
        continue
    any_eligible = True
    deltas = [summary[i]["line_pct"] - summary[i-1]["line_pct"]
              for i in range(1, len(summary))]
    last_two = deltas[-2:]
    if not all(d < threshold for d in last_two):
        sys.exit(1)  # this harness still gaining → keep looping

# Plateau only if at least one harness was eligible AND all of them plateaued.
sys.exit(0 if any_eligible else 1)
PY
}

echo "[run_fuzzing] === step 1/6: install AFL++ + tooling ==="
"$SCRIPT_DIR/install_afl.sh"

# Make sure the freshly-installed AFL++ binaries are on PATH for this shell.
export PATH="${HOME}/.local/opt/AFLplusplus/bin:${PATH}"

start_dashboard

echo "[run_fuzzing] === step 2/6: fetch source code ==="
run_taskflow seclab_taskflows.taskflows.audit.fetch_source_code

echo "[run_fuzzing] === step 3/6: identify fuzz targets ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.identify_fuzz_targets

echo "[run_fuzzing] === step 4/6: analyse build system ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.analyze_build_system

echo "[run_fuzzing] === step 5/6: initial harnesses + builds ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.write_initial_harnesses \
  -g "harness_candidates=$HARNESS_CANDIDATES"
run_taskflow seclab_taskflows.taskflows.fuzzing.build_harnesses

if [ "$HARNESS_CANDIDATES" -gt 1 ]; then
  echo "[run_fuzzing] === step 5b/6: qualifier — pick best of $HARNESS_CANDIDATES candidates ==="
  run_taskflow seclab_taskflows.taskflows.fuzzing.qualify_harnesses \
    -g "qualifier_seconds=$QUALIFIER_SECONDS"
fi

echo "[run_fuzzing] === step 6/6: fuzz / coverage / improve loop ==="
i=1
for budget in "${SCHEDULE[@]}"; do
  echo "[run_fuzzing] iteration $i (budget = ${budget}s)"
  run_taskflow seclab_taskflows.taskflows.fuzzing.fuzz_iteration \
    -g "iteration=$i" -g "time_budget_seconds=$budget"
  if plateau_reached; then
    echo "[run_fuzzing] coverage plateau detected — stopping loop early"
    break
  fi
  i=$((i + 1))
done

echo "[run_fuzzing] === triage crashes ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.triage_crashes || true

echo "[run_fuzzing] === confirm previously-known crashes are still reproducible ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.confirm_fixed_crashes || true

echo "[run_fuzzing] === analyse call graph + untouched API surface ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.analyze_call_graph || true

echo "[run_fuzzing] === write per-crash vuln reports ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.write_vuln_reports || true

echo "[run_fuzzing] === write report ==="
run_taskflow seclab_taskflows.taskflows.fuzzing.write_report

set +e
# Open the results database in VS Code if running inside a codespace.
if [ -v CODESPACES ]; then
  RESULTS_DB="$HOME/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_context/fuzz_context.db"
  if [ -f "$RESULTS_DB" ] && command -v code >/dev/null 2>&1; then
    code "$RESULTS_DB"
  fi
fi

echo "[run_fuzzing] done"
