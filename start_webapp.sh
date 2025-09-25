#!/bin/bash
# OSINT Suite Full Web Application Startup
# Runs both the API server and web frontend

set -e

echo "🌐 OSINT Suite Full Web Application"
echo "==================================="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "📂 Running from: $SCRIPT_DIR"

# Check if we're in the right directory
if [ ! -f "api/api_server.py" ] || [ ! -d "web" ]; then
    echo "❌ Error: Required files not found in $SCRIPT_DIR"
    echo "Expected: api/api_server.py and web/ directory"
    echo "Found files:"
    ls -la
    exit 1
fi

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Error: Virtual environment not found. Please run setup first."
    exit 1
fi

# Check if web app is built
if [ ! -f "web/dist/index.html" ]; then
    echo "⚠️  Warning: Web app not built. Building now..."
    cd web
    if [ -f "package.json" ]; then
        npm run build
    else
        echo "❌ Error: Web app package.json not found. Cannot build web app."
        exit 1
    fi
    cd ..
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Set environment variables
export OSINT_USE_KEYRING=false
export OSINT_TEST_MODE=false
export PYTHONPATH="$(pwd)"

# Create necessary directories
echo "📁 Creating output directories..."
mkdir -p output/encrypted output/audit output/logs logs policies

# Set ports
API_PORT=${API_PORT:-8000}
WEB_PORT=${WEB_PORT:-3000}

echo "🚀 Starting OSINT Suite Web Application"
echo "======================================="
echo "📡 API Server: http://localhost:$API_PORT"
echo "🌐 Web App:    http://localhost:$WEB_PORT"
echo "📖 API Docs:   http://localhost:$API_PORT/docs"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    kill $API_PID $WEB_PID 2>/dev/null || true
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Start API server in background
echo "🔄 Starting API server on port $API_PORT..."
python -m uvicorn api.api_server:app --host 0.0.0.0 --port $API_PORT --reload &
API_PID=$!

# Wait a moment for API to start
sleep 3

# Start web server in background
echo "🔄 Starting web app server on port $WEB_PORT..."
cd web/dist
python -m http.server $WEB_PORT &
WEB_PID=$!

# Wait for both to be ready
sleep 2

echo "✅ Services started successfully!"
echo "🌐 Open http://localhost:$WEB_PORT in your browser"
echo ""
echo "API Health Check: curl http://localhost:$API_PORT/health"
echo ""

# Wait for processes
wait $API_PID $WEB_PID