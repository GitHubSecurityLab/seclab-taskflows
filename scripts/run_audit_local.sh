#!/bin/bash
# Local audit runner script
set -e

# Check if venv exists
if [ ! -d ".venv" ]; then
    echo "Error: Virtual environment not found"
    echo "Please run ./setup_local.sh first"
    exit 1
fi

# Check for required argument
if [ -z "$1" ]; then
    echo "Usage: $0 <repo>"
    echo "Example: $0 juice-shop/juice-shop"
    exit 1
fi

REPO="$1"

# Create timestamped and project-named directories
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PROJECT_NAME=$(echo "$REPO" | sed 's/\//_/g')
AUDIT_DIR="$HOME/.local/share/seclab-taskflow-agent/audits/${PROJECT_NAME}_${TIMESTAMP}"
DATA_DIR="${AUDIT_DIR}/data"
LOG_FILE="${AUDIT_DIR}/audit.log"

# Create audit directory structure
mkdir -p "${DATA_DIR}"
mkdir -p "${AUDIT_DIR}/logs"

echo "Audit directory: ${AUDIT_DIR}"
echo "Data directory: ${DATA_DIR}"
echo "Log file: ${LOG_FILE}"

# Check for gh CLI and get token
if ! command -v gh &> /dev/null; then
    echo "Error: gh CLI is required but not found"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Get Copilot API token from passage
if ! command -v passage &> /dev/null; then
    echo "Error: passage command not found"
    echo "Install passage or ensure your Copilot API token is available"
    exit 1
fi

CAPI_TOKEN=$(passage show github/capi-token 2>/dev/null)
if [ -z "$CAPI_TOKEN" ]; then
    echo "Error: Unable to retrieve github/capi-token from passage"
    echo "Please ensure your Copilot API token is stored with: passage insert github/capi-token"
    exit 1
fi

# Export tokens if not already set
if [ -z "$GH_TOKEN" ]; then
    export GH_TOKEN="$CAPI_TOKEN"
fi

if [ -z "$AI_API_TOKEN" ]; then
    export AI_API_TOKEN="$CAPI_TOKEN"
fi

# Set default AI endpoint if not provided
if [ -z "$AI_API_ENDPOINT" ]; then
    export AI_API_ENDPOINT="https://api.githubcopilot.com"
fi

# Set environment variables to redirect data stores to timestamped directory
# DATA_DIR is the primary variable used by all toolbox configurations
# Following the pattern from README.md for consistency
export DATA_DIR="${DATA_DIR}"
export MEMCACHE_STATE_DIR="${DATA_DIR}"
export CODEQL_DBS_BASE_PATH="${DATA_DIR}"
export LOG_DIR="${AUDIT_DIR}/logs"

# Activate virtual environment
source .venv/bin/activate

# Redirect all output to both console and log file
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "========================================"
echo "Starting audit of $REPO"
echo "========================================"
echo "Audit directory: ${AUDIT_DIR}"
echo "Timestamp: ${TIMESTAMP}"
echo "AI Endpoint: $AI_API_ENDPOINT"
echo "Log file: ${LOG_FILE}"
echo "========================================"
echo ""

# Run the audit taskflows
echo "Step 1/5: Fetching source code..."
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.fetch_source_code -g repo="$REPO"

echo ""
echo "Step 2/5: Identifying applications..."
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.identify_applications -g repo="$REPO"

echo ""
echo "Step 3/5: Gathering web entry point info..."
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.gather_web_entry_point_info -g repo="$REPO"

echo ""
echo "Step 4/5: Classifying applications..."
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.classify_application_local -g repo="$REPO"

echo ""
echo "Step 5/5: Running audit..."
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.audit_issue_local_iter -g repo="$REPO"

# Locate and display results
# The repo_context MCP server creates the database at ${DATA_DIR}/repo_context.db
RESULTS_DB="${DATA_DIR}/repo_context.db"

echo ""
echo "========================================"
echo "Audit complete!"
echo "========================================"
echo ""

if [ -f "$RESULTS_DB" ]; then
    echo "Results database location:"
    echo "  $RESULTS_DB"
    echo ""
    echo "Audit directory:"
    echo "  $AUDIT_DIR"
    echo ""
    echo "Log file:"
    echo "  $LOG_FILE"
    echo ""
    echo "Results are in the 'audit_result' table."
    echo "Rows with has_vulnerability=true are most likely to be genuine vulnerabilities."
    echo ""

    # Generate vulnerability reports
    echo "Generating vulnerability reports..."
    python3 scripts/generate_vuln_reports.py "$RESULTS_DB"
    VULN_REPORTS_DIR="${DATA_DIR}/vulns"

    if [ -d "$VULN_REPORTS_DIR" ]; then
        VULN_COUNT=$(find "$VULN_REPORTS_DIR" -name "summary.md" | wc -l | tr -d ' ')
        echo ""
        echo "Generated $VULN_COUNT vulnerability report(s):"
        echo "  $VULN_REPORTS_DIR"
        echo ""
    fi

    # Create agent_out directory with consolidated outputs
    echo "Creating agent output package..."
    AGENT_OUT_DIR="${AUDIT_DIR}/agent_out"
    mkdir -p "${AGENT_OUT_DIR}"

    # Copy audit log
    if [ -f "$LOG_FILE" ]; then
        cp "$LOG_FILE" "${AGENT_OUT_DIR}/"
        echo "  ✓ Copied audit.log"
    fi

    # Copy database
    if [ -f "$RESULTS_DB" ]; then
        cp "$RESULTS_DB" "${AGENT_OUT_DIR}/"
        echo "  ✓ Copied repo_context.db"
    fi

    # Copy vulnerability reports
    if [ -d "$VULN_REPORTS_DIR" ]; then
        cp -r "$VULN_REPORTS_DIR" "${AGENT_OUT_DIR}/"
        echo "  ✓ Copied vulns/"
    fi

    echo ""
    echo "Agent output package created:"
    echo "  $AGENT_OUT_DIR"
    echo ""

    echo "========================================"
    echo "Output Locations:"
    echo "========================================"
    echo "Database:  $RESULTS_DB"
    echo "Reports:   $VULN_REPORTS_DIR"
    echo "Logs:      $LOG_FILE"
    echo "Package:   $AGENT_OUT_DIR"
    echo ""

    # Try to open with sqlite3 if available
    if command -v sqlite3 &> /dev/null; then
        echo "To view results with sqlite3:"
        echo "  sqlite3 \"${AGENT_OUT_DIR}/repo_context.db\" 'SELECT * FROM audit_result WHERE has_vulnerability = 1;'"
    fi

    # Try to open in VS Code if available
    if command -v code &> /dev/null; then
        echo ""
        read -p "Open results in VS Code? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            code "$AGENT_OUT_DIR"
        fi
    fi
else
    echo "Warning: Results database not found at expected location"
    echo "Expected: $RESULTS_DB"
    echo ""
    echo "Audit directory contents:"
    ls -lR "$AUDIT_DIR"
fi

echo ""
echo "========================================"
echo "All output has been logged to: $LOG_FILE"
echo "========================================"
