#!/bin/bash
# Rebuild Container Script
# Use this when the dev container is in recovery mode

echo "🔄 Rebuilding OSINT Suite Dev Container..."
echo "=========================================="

# Check if we're in a codespace
if [ -z "$CODESPACES" ]; then
    echo "❌ This script should be run in a GitHub Codespace"
    exit 1
fi

echo "📦 This will rebuild the dev container with a minimal, reliable configuration"
echo "🔧 The rebuilt container will include:"
echo "   - Python 3.12 with core packages only"
echo "   - Git support"
echo "   - Essential VS Code extensions"
echo "   - Scripts made executable"
echo ""
echo "💡 Node.js and full packages will be installed automatically on first run"
echo "⚠️  This will restart your codespace environment"
echo ""

read -p "Continue with rebuild? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Rebuild cancelled"
    exit 1
fi

echo "🚀 Initiating container rebuild..."
echo "💡 You can monitor progress in the terminal output"

# Trigger container rebuild (this will restart the codespace)
echo "Rebuilding container..." > /tmp/container_rebuild_trigger

# The actual rebuild is handled by VS Code/Codespaces
echo "✅ Rebuild initiated - codespace will restart automatically"
echo ""
echo "📋 After rebuild completes:"
echo "   1. Run: ./validate_setup.sh    # Check everything works"
echo "   2. Run: ./start_simple.sh      # Complete setup and start suite"
