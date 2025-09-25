#!/bin/bash
# OSINT Suite - Simple Startup Script
# Launches both backend API and web frontend

set -e

cd "$(dirname "$0")"

echo "🚀 Starting Passive OSINT Suite..."
echo "=================================="

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Please run install.sh first."
    exit 1
fi

# Activate virtual environment
echo "📦 Activating Python virtual environment..."
source .venv/bin/activate

# Check if full requirements are installed
if ! python -c "import transformers, torch, elasticsearch, neo4j" 2>/dev/null; then
    echo "📦 Installing full requirements (this may take a few minutes)..."
    pip install --no-cache-dir -r requirements.txt
    echo "✅ Full requirements installed"
else
    echo "✅ Full requirements already installed"
fi

# Set Python path
export PYTHONPATH="$PWD:$PYTHONPATH"

# Run health checks
echo "🏥 Running pre-startup health checks..."
if python3 health_check.py; then
    echo "✅ Health checks passed"
else
    echo "⚠️  Health checks completed with warnings - continuing anyway"
fi

echo ""

# Check and start Tor service
echo "🧅 Checking Tor service..."
if command -v tor >/dev/null 2>&1; then
    if ! pgrep -x "tor" > /dev/null; then
        echo "🔧 Starting Tor service..."
        sudo systemctl start tor 2>/dev/null || sudo service tor start 2>/dev/null || {
            echo "⚠️  Could not start Tor system service, attempting manual start..."
            tor --quiet &
            TOR_PID=$!
            sleep 5
            if ! kill -0 $TOR_PID 2>/dev/null; then
                echo "❌ Failed to start Tor"
            else
                echo "✅ Tor started manually (PID: $TOR_PID)"
            fi
        }
    else
        echo "✅ Tor service is running"
    fi
else
    echo "⚠️  Tor not installed - anonymity features will be limited"
fi

# Check if Node.js dependencies are installed and npm is available
if [ ! -d "web/node_modules" ] || ! command -v npm >/dev/null 2>&1; then
    echo "📦 Setting up Node.js and web dependencies..."
    
    # Try to install Node.js if not available
    if ! command -v node >/dev/null 2>&1; then
        echo "🔧 Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && \
        sudo apt-get install -y nodejs
    fi
    
    # Install web dependencies
    if command -v npm >/dev/null 2>&1; then
        echo "📦 Installing web dependencies..."
        cd web
        npm install
        cd ..
        echo "✅ Web dependencies installed"
    else
        echo "⚠️  npm not available - web interface will not be available"
        SKIP_WEB=true
    fi
fi

# Function to find next available port
find_next_port() {
    local port=$1
    while lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; do
        port=$((port + 1))
    done
    echo $port
}

# Find available ports
API_PORT=$(find_next_port 8000)
WEB_PORT=$(find_next_port 3001)

echo "🔍 Using ports: API=$API_PORT, Web=$WEB_PORT"

# Start API server in background
echo "🔧 Starting FastAPI backend on port $API_PORT..."
python api/api_server.py &
API_PID=$!

# Wait a moment for API to start
sleep 3

# Check if API is running
if ! kill -0 $API_PID 2>/dev/null; then
    echo "❌ Failed to start API server"
    exit 1
fi

echo "✅ API server started (PID: $API_PID)"

# Start web frontend in background (if available)
if [ "$SKIP_WEB" != "true" ]; then
    echo "🌐 Starting web frontend on port $WEB_PORT..."
    cd web
    PORT=$WEB_PORT npm run dev &
    WEB_PID=$!

    cd ..

    # Wait a moment for web to start
    sleep 5

    # Check if web is running
    if ! kill -0 $WEB_PID 2>/dev/null; then
        echo "❌ Failed to start web frontend"
        kill $API_PID 2>/dev/null || true
        exit 1
    fi

    echo "✅ Web frontend started (PID: $WEB_PID)"
else
    WEB_PID=""
fi

echo ""
echo "🎉 OSINT Suite is now running!"
echo "================================"
echo "📊 Web Interface: http://localhost:$WEB_PORT"
echo "🔌 API Backend:   http://localhost:$API_PORT"
echo "📚 API Docs:      http://localhost:$API_PORT/docs"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for user interrupt
trap 'echo ""; echo "🛑 Stopping services..."; kill $API_PID 2>/dev/null || true; [ -n "$WEB_PID" ] && kill $WEB_PID 2>/dev/null || true; [ -n "$TOR_PID" ] && kill $TOR_PID 2>/dev/null || true; echo "✅ All services stopped"; exit 0' INT

# Keep script running
wait
