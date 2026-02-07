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

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env template..."
    # Test whether a simple curl command to api.githubcopilot.com works. If so
    # install the Copilot version of .env, otherwise install the default version.
    ENV_VERSION="env-default"
    if [ -v AI_API_TOKEN ]; then
        if curl --fail --silent --show-error https://api.githubcopilot.com/models -H "Authorization: Bearer $AI_API_TOKEN" -H "Copilot-Integration-Id: vscode-chat" > /dev/null; then
            ENV_VERSION="env-copilot"
        fi
    fi
    cp ".devcontainer/${ENV_VERSION}" .env || { echo "Error creating .env"; exit 1; }
    code .env || echo "ℹ️ Unable to open .env in VS Code. Please open and review the .env file manually."
    echo "⚠️  Defaults can be changed by editing the auto-generated .env file."
fi

echo "💡 Remember to activate the virtual environment: source .venv/bin/activate"
