#!/bin/bash
# Validate OSINT Suite Setup
# Run this after container rebuild to check everything is working

echo "🔍 Validating OSINT Suite Setup..."
echo "==================================="

# Check Python
echo "🐍 Checking Python..."
if command -v python >/dev/null 2>&1; then
    PYTHON_VERSION=$(python --version 2>&1)
    echo "✅ Python available: $PYTHON_VERSION"
else
    echo "❌ Python not found"
    exit 1
fi

# Check pip
echo "📦 Checking pip..."
if command -v pip >/dev/null 2>&1; then
    echo "✅ pip available"
else
    echo "❌ pip not found"
    exit 1
fi

# Check virtual environment
echo "🌐 Checking virtual environment..."
if [ -d ".venv" ]; then
    echo "✅ Virtual environment exists"
else
    echo "❌ Virtual environment missing - run install.sh first"
fi

# Check scripts are executable
echo "⚙️  Checking scripts..."
if [ -x "start_simple.sh" ]; then
    echo "✅ start_simple.sh is executable"
else
    echo "⚠️  Making scripts executable..."
    chmod +x *.sh
    chmod +x scripts/*.sh 2>/dev/null || true
    echo "✅ Scripts made executable"
fi

# Check Node.js (optional)
echo "🌐 Checking Node.js (optional for web interface)..."
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node --version 2>&1)
    echo "✅ Node.js available: $NODE_VERSION"
    if command -v npm >/dev/null 2>&1; then
        NPM_VERSION=$(npm --version 2>&1)
        echo "✅ npm available: $NPM_VERSION"
    else
        echo "⚠️  npm not available - web interface will install it automatically"
    fi
else
    echo "⚠️  Node.js not available - will be installed automatically on first run"
fi

# Check core Python packages
echo "🔧 Checking core Python packages..."
source .venv/bin/activate 2>/dev/null || true
python -c "
try:
    import fastapi, uvicorn, requests, rich
    print('✅ Core packages available')
except ImportError as e:
    print(f'⚠️  Some packages missing: {e}')
    print('   Run ./start_simple.sh to install full requirements')
"

echo ""
echo "🎉 Validation complete!"
echo "======================"
echo "💡 Run ./start_simple.sh to complete setup and start the suite"
echo "🌐 Web interface will be available at http://localhost:3001"
echo "🔌 API will be available at http://localhost:8000"
