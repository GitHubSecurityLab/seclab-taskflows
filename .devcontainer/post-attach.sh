#!/bin/bash
set -e

# If running in Codespaces, check for necessary secrets and print error if missing
if [ -v CODESPACES ]; then
    echo "🔐 Running in Codespaces - injecting secrets from Codespaces settings..."
    if [ ! -v AI_API_TOKEN ]; then
        echo "⚠️ Running in Codespaces - please add AI_API_TOKEN to your Codespaces secrets"
    fi
    if [ ! -v GH_TOKEN ]; then
        echo "⚠️ Running in Codespaces - please add GH_TOKEN to your Codespaces secrets"
    fi
fi

echo "💡 Remember to activate the virtual environment: source .venv/bin/activate"
