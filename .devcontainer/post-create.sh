#!/bin/bash
set -e

echo "🚀 Setting up Seclab Taskflows development environment..."

# Create Python virtual environment
echo "📦 Creating Python virtual environment..."
python3 -m venv .venv

# Activate virtual environment and install dependencies
echo "📥 Installing Python dependencies..."
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install hatch
hatch build

# Install this package from local directory.
pip install -e .

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env template..."
    cp .devcontainer/env-default .env || { echo "Error creating .env"; exit 1; }
    echo "⚠️  Defaults can be changed by editing the auto-generated .env file."
fi

echo "✅ Development environment setup complete!"
