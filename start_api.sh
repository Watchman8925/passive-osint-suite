#!/bin/bash
# OSINT Suite API Server Direct Startup
# Run the FastAPI server without Docker

set -e

echo "🌐 OSINT Suite API Server Startup"
echo "================================="

# Check if we're in the right directory
if [ ! -f "api/api_server.py" ]; then
    echo "❌ Error: api/api_server.py not found. Please run this script from the OSINT suite directory."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Error: Virtual environment not found. Please run setup first."
    exit 1
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

# Set default host and port
HOST=${HOST:-0.0.0.0}
PORT=${PORT:-8000}

echo "🚀 Starting FastAPI server on http://$HOST:$PORT"
echo "📖 API documentation available at: http://$HOST:$PORT/docs"
echo "🔄 Realtime docs at: http://$HOST:$PORT/redoc"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the API server
python -m uvicorn api.api_server:app --host $HOST --port $PORT --reload