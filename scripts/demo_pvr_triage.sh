#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT
#
# Live demo of PVR triage taskflows against anticomputer/vulnerable-test-app.
#
# Exercises: advisory listing, dedup detection, security policy fetch,
# code verification, report generation, and batch scoring.
#
# Prerequisites:
#   - gh CLI authenticated
#   - passage available for AI token
#   - seclab-taskflows installed in .venv
#
# Usage:
#   ./scripts/demo_pvr_triage.sh [tools|batch|triage|all]
#
#   tools   - test individual MCP tools against live API (fast, no AI calls)
#   batch   - run the batch scoring taskflow
#   triage  - run full single-advisory triage on the high-quality report
#   all     - run everything in sequence

set -euo pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__root="$(cd "${__dir}/.." && pwd)"

REPO="anticomputer/vulnerable-test-app"
# Advisory state: "draft" for owner-created test advisories,
# "triage" for real PVR submissions from external reporters.
ADVISORY_STATE="${ADVISORY_STATE:-draft}"

# --- environment ---

if [ -d "${__root}/.venv/bin" ]; then
    export PATH="${__root}/.venv/bin:${PATH}"
fi

export GH_TOKEN="${GH_TOKEN:-$(gh auth token 2>/dev/null)}"
if [ -z "${GH_TOKEN}" ]; then
    echo "FATAL: gh auth token failed. Run: gh auth login" >&2
    exit 1
fi

export AI_API_TOKEN="${AI_API_TOKEN:-$(passage show github/capi-token 2>/dev/null)}"
if [ -z "${AI_API_TOKEN}" ]; then
    echo "FATAL: AI_API_TOKEN not set and passage unavailable." >&2
    exit 1
fi

export AI_API_ENDPOINT="${AI_API_ENDPOINT:-https://api.githubcopilot.com}"
export REPORT_DIR="${REPORT_DIR:-${__root}/reports/demo}"
export LOG_DIR="${LOG_DIR:-${__root}/logs}"
mkdir -p "${REPORT_DIR}" "${LOG_DIR}"

# --- helpers ---

sep() { echo; echo "========== $1 =========="; echo; }
ok()  { echo "[OK] $1"; }
fail() { echo "[FAIL] $1" >&2; FAILURES=$((FAILURES + 1)); }

FAILURES=0

run_agent() {
    python -m seclab_taskflow_agent "$@"
}

# --- tools: test individual MCP tools against live API ---

cmd_tools() {
    sep "MCP Tool Tests (live API, no AI calls)"

    echo "--- list_pvr_advisories (state=draft) ---"
    ADVISORIES=$(python -c "
import seclab_taskflows.mcp_servers.pvr_ghsa as pvr
print(pvr.list_pvr_advisories.fn(owner='anticomputer', repo='vulnerable-test-app', state='draft'))
")
    COUNT=$(echo "$ADVISORIES" | python -c "import sys,json; print(len(json.load(sys.stdin)))")
    if [ "$COUNT" -ge 1 ]; then
        ok "Found $COUNT advisories in draft state"
    else
        fail "No advisories found. Create test advisories first."
        return
    fi
    echo "$ADVISORIES" | python -c "
import sys, json
for a in json.load(sys.stdin):
    print(f\"  {a['ghsa_id']}  {a['severity']:8s}  {a['summary']}\")
"
    echo

    echo "--- fetch_pvr_advisory (first advisory) ---"
    GHSA=$(echo "$ADVISORIES" | python -c "import sys,json; print(json.load(sys.stdin)[0]['ghsa_id'])")
    DETAIL=$(python -c "
import seclab_taskflows.mcp_servers.pvr_ghsa as pvr
print(pvr.fetch_pvr_advisory.fn(owner='anticomputer', repo='vulnerable-test-app', ghsa_id='${GHSA}'))
")
    if echo "$DETAIL" | python -c "import sys,json; d=json.load(sys.stdin); assert d['ghsa_id']" 2>/dev/null; then
        ok "Fetched ${GHSA}: $(echo "$DETAIL" | python -c "import sys,json; d=json.load(sys.stdin); print(f\"{d['severity']} - CWEs: {d['cwes']}\")")"
    else
        fail "Failed to fetch ${GHSA}"
    fi
    echo

    echo "--- fetch_security_policy ---"
    POLICY=$(python -c "
import seclab_taskflows.mcp_servers.pvr_ghsa as pvr
print(pvr.fetch_security_policy.fn(owner='anticomputer', repo='vulnerable-test-app'))
")
    if [ -n "$POLICY" ]; then
        ok "Security policy found ($(echo "$POLICY" | wc -l | tr -d ' ') lines)"
        echo "$POLICY" | head -5 | sed 's/^/  /'
        echo "  ..."
    else
        fail "No security policy found"
    fi
    echo

    echo "--- compare_advisories (dedup detection) ---"
    DEDUP=$(python -c "
import seclab_taskflows.mcp_servers.pvr_ghsa as pvr
print(pvr.compare_advisories.fn(owner='anticomputer', repo='vulnerable-test-app', state='draft', target_ghsa=''))
")
    CLUSTERS=$(echo "$DEDUP" | python -c "import sys,json; print(len(json.load(sys.stdin)['clusters']))")
    TOTAL=$(echo "$DEDUP" | python -c "import sys,json; print(json.load(sys.stdin)['total'])")
    ok "Compared $TOTAL advisories, found $CLUSTERS duplicate cluster(s)"
    echo "$DEDUP" | python -c "
import sys, json
d = json.load(sys.stdin)
for c in d['clusters']:
    print(f\"  Cluster [{c['match_level']}]: {', '.join(c['advisories'])}\")
    for r in c['reasons']:
        print(f\"    - {r}\")
for s in d['singles']:
    print(f\"  Single: {s}\")
"
    echo

    echo "--- fetch_file_at_ref (main.go lines 25-30) ---"
    CODE=$(python -c "
import seclab_taskflows.mcp_servers.pvr_ghsa as pvr
print(pvr.fetch_file_at_ref.fn(owner='anticomputer', repo='vulnerable-test-app', path='main.go', ref='main', start_line=25, length=6))
")
    if echo "$CODE" | grep -q "searchHandler"; then
        ok "Fetched vulnerable code at main.go:25"
        echo "$CODE" | sed 's/^/  /'
    else
        fail "Failed to fetch main.go"
    fi
    echo

    echo "--- resolve_version_ref (0.0.1 -- expected to fail, no tags) ---"
    VER=$(python -c "
import seclab_taskflows.mcp_servers.pvr_ghsa as pvr
print(pvr.resolve_version_ref.fn(owner='anticomputer', repo='vulnerable-test-app', version='0.0.1'))
")
    if echo "$VER" | grep -q "Could not resolve"; then
        ok "Graceful failure: no tags in repo (expected)"
    else
        ok "Resolved: $VER"
    fi
    echo

    sep "Tool Tests Complete ($FAILURES failures)"
}

# --- batch: run batch scoring taskflow ---

cmd_batch() {
    sep "Batch Scoring Taskflow"
    echo "Repo: ${REPO}"
    echo "Report dir: ${REPORT_DIR}"
    echo

    # The test advisories are in draft state (owner-created), so patch the
    # taskflow call to use state=draft. The batch taskflow defaults to triage
    # state, but we can override via the run_agent globals.
    run_agent \
        -t seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch \
        -g "repo=${REPO}" \
        -g "state=${ADVISORY_STATE}"

    echo
    BATCH_REPORT=$(ls -t "${REPORT_DIR}"/batch_queue_*.md 2>/dev/null | head -1)
    if [ -n "${BATCH_REPORT}" ]; then
        ok "Batch report: ${BATCH_REPORT}"
        echo
        cat "${BATCH_REPORT}"
    else
        fail "No batch report generated"
    fi
}

# --- triage: run full single-advisory triage ---

cmd_triage() {
    local ghsa="${1:-}"

    if [ -z "$ghsa" ]; then
        # Pick the high-quality SQL injection report
        ghsa=$(python -c "
import json, seclab_taskflows.mcp_servers.pvr_ghsa as pvr
advs = json.loads(pvr.list_pvr_advisories.fn(owner='anticomputer', repo='vulnerable-test-app', state='draft'))
for a in advs:
    if 'SQL' in a['summary'] or 'sql' in a['summary'].lower():
        print(a['ghsa_id'])
        break
else:
    print(advs[0]['ghsa_id'] if advs else '')
")
    fi

    if [ -z "$ghsa" ]; then
        fail "No advisories found to triage"
        return
    fi

    sep "Single Advisory Triage: ${ghsa}"
    echo "Repo: ${REPO}"
    echo "GHSA: ${ghsa}"
    echo "Report dir: ${REPORT_DIR}"
    echo

    run_agent \
        -t seclab_taskflows.taskflows.pvr_triage.pvr_triage \
        -g "repo=${REPO}" \
        -g "ghsa=${ghsa}" \
        -g "state=${ADVISORY_STATE}"

    echo
    TRIAGE_REPORT="${REPORT_DIR}/${ghsa}_triage.md"
    RESPONSE_DRAFT="${REPORT_DIR}/${ghsa}_response_triage.md"
    if [ -f "${TRIAGE_REPORT}" ]; then
        ok "Triage report: ${TRIAGE_REPORT}"
        echo
        cat "${TRIAGE_REPORT}"
    else
        fail "No triage report generated"
    fi
    echo
    if [ -f "${RESPONSE_DRAFT}" ]; then
        sep "Response Draft"
        cat "${RESPONSE_DRAFT}"
    fi
}

# --- all: run everything ---

cmd_all() {
    cmd_tools
    cmd_batch
    cmd_triage "${1:-}"
    sep "Demo Complete ($FAILURES total failures)"
}

# --- dispatch ---

case "${1:-tools}" in
    tools)   cmd_tools ;;
    batch)   cmd_batch ;;
    triage)  shift; cmd_triage "${1:-}" ;;
    all)     shift; cmd_all "${1:-}" ;;
    -h|--help|help)
        echo "Usage: $0 [tools|batch|triage [GHSA]|all]"
        echo
        echo "  tools   - test MCP tools against live API (no AI calls)"
        echo "  batch   - run batch scoring taskflow"
        echo "  triage  - run full triage (picks SQL injection report by default)"
        echo "  all     - run everything in sequence"
        ;;
    *) echo "Unknown command: $1" >&2; exit 1 ;;
esac
