#!/bin/bash
# Setup script for local development environment
set -e

echo "Setting up Seclab Taskflows local environment..."

# Check for gh CLI and get token
if ! command -v gh &> /dev/null; then
    echo "Error: gh CLI is required but not found"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Export tokens from gh CLI
export GH_TOKEN=$(gh auth token 2>/dev/null)
export AI_API_TOKEN=$(gh auth token 2>/dev/null)

if [ -z "$GH_TOKEN" ]; then
    echo "Error: Unable to get GitHub token from gh CLI"
    echo "Please run: gh auth login"
    exit 1
fi

echo "Tokens configured from gh CLI"

# Check Python version - try to find Python 3.10-3.13 (3.14 not yet supported by pydantic-core)
PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v $cmd &> /dev/null; then
        VERSION=$($cmd -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        # Check if version is >= 3.10 and <= 3.13
        if [ "$(printf '%s\n' "3.10" "$VERSION" | sort -V | head -n1)" = "3.10" ] && \
           [ "$(printf '%s\n' "$VERSION" "3.13" | sort -V | head -n1)" = "$VERSION" ]; then
            PYTHON_CMD=$cmd
            echo "Found $cmd (Python $VERSION)"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "Error: Python >= 3.10 is required for seclab-taskflow-agent"
    echo "Please install Python 3.10 or later"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment with $PYTHON_CMD..."
    $PYTHON_CMD -m venv .venv
else
    echo "Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install hatch for building
echo "Installing hatch..."
python -m pip install hatch

# Build the package
echo "Building package..."
hatch build

# Install package in editable mode
echo "Installing seclab-taskflows in editable mode..."
pip install -e .

echo ""
echo "Setup complete!"
echo ""
echo "To activate the environment, run:"
echo "  source .venv/bin/activate"
echo ""
echo "Required environment variables:"
echo "  GH_TOKEN          - GitHub token for API access"
echo "  AI_API_TOKEN      - AI API token (GitHub Models or other)"
echo "  AI_API_ENDPOINT   - (optional) defaults to https://models.github.ai/inference"
echo ""
echo "Optional environment variables:"
echo "  MEMCACHE_STATE_DIR - Directory for memcache state"
echo "  DATA_DIR           - Directory for intermediate results"
echo "  LOG_DIR            - Directory for log files"
echo ""
