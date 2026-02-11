#!/bin/bash
set -e

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env template..."
    touch .env

    # Test whether api.githubcopilot.com works with the GITHUB_TOKEN
    # provided by the codespace. If so, configure .env to use that token.
    USE_GITHUB_TOKEN="false"
    if [ ! -v AI_API_TOKEN ] && [ -v CODESPACES ] && [ -v GITHUB_TOKEN ]; then
        if curl --fail --silent --show-error https://api.githubcopilot.com/models -H "Authorization: Bearer $GITHUB_TOKEN" > /dev/null; then
            USE_GITHUB_TOKEN="true"
            echo 'AI_API_TOKEN=${GITHUB_TOKEN}' >> .env
            if [ ! -v GH_TOKEN ]; then
                echo 'GH_TOKEN=${GITHUB_TOKEN}' >> .env
            fi
            echo >> .env
        fi
    fi

    # If running in Codespaces, check for necessary secrets and print error if missing
    if [ -v CODESPACES ]; then
        if [[ "$USE_GITHUB_TOKEN" == "false" ]]; then
           if [ ! -v AI_API_TOKEN ]; then
               echo "⚠️ Running in Codespaces - please add AI_API_TOKEN to your Codespaces secrets"
           fi
           if [ ! -v GH_TOKEN ]; then
               echo "⚠️ Running in Codespaces - please add GH_TOKEN to your Codespaces secrets"
           fi
        fi
    fi

    echo "# Uncomment the endpoint that you want to use:" >> .env
    echo "#AI_API_ENDPOINT=https://models.github.ai/inference" >> .env
    echo "#AI_API_ENDPOINT=https://api.openai.com/v1" >> .env

    # Use api.githubcopilot.com by default if USE_GITHUB_TOKEN is true.
    if [[ "$USE_GITHUB_TOKEN" == "true" ]]; then
        echo "AI_API_ENDPOINT=https://api.githubcopilot.com" >> .env
    else
        echo "#AI_API_ENDPOINT=https://api.githubcopilot.com" >> .env
    fi

    echo >> .env
    echo "# Uncomment to set the model temperature" >> .env
    echo "#MODEL_TEMP=1.0" >> .env
    echo >> .env
    echo "# Optional data storage directories. By default, ~/.local is used." >> .env
    echo "#MEMCACHE_STATE_DIR=/app/data" >> .env
    echo "#CODEQL_DBS_BASE_PATH=/app/data" >> .env
    echo "#DATA_DIR=/app/data" >> .env
    echo "#LOG_DIR=/app/logs" >> .env

    code .env || echo "ℹ️ Unable to open .env in VS Code. Please open and review the .env file manually."
    echo "⚠️  Defaults can be changed by editing the auto-generated .env file."
fi

echo "💡 Remember to activate the virtual environment: source .venv/bin/activate"
