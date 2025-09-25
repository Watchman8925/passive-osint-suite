#!/bin/bash
# OSINT Suite Direct Startup Script
# Run the OSINT suite without Docker containers

set -e

echo "🚀 OSINT Suite Direct Startup"
echo "============================"

# Check if we're in the right directory
if [ ! -f "osint_suite.py" ]; then
    echo "❌ Error: osint_suite.py not found. Please run this script from the OSINT suite directory."
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

# Run the OSINT suite
echo "🎯 Starting OSINT Suite..."
echo ""
echo "Available commands:"
echo "  --help          Show help"
echo "  --domain DOMAIN Analyze specific domain"
echo "  --email EMAIL   Analyze specific email"
echo "  --ip IP         Analyze specific IP"
echo "  --company COMPANY Analyze specific company"
echo "  --quiet         Quiet mode (shows interactive menu)"
echo ""
echo "Or run without arguments for interactive mode."
echo ""

python osint_suite.py "$@"