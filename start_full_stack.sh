#!/bin/bash
# Start the full OSINT Suite stack (backend + frontend)
# This script starts both services and handles cleanup on exit

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  OSINT Suite Full Stack Launcher${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if .env file exists, create it if not
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file not found, creating from .env.example...${NC}"
    if [ -f .env.example ]; then
        # Generate a secure random secret key
        SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
        
        # Create .env with generated secret
        cat > .env << EOF
# Auto-generated .env file for OSINT Suite
# Edit this file to customize settings

# Critical Security Settings
OSINT_SECRET_KEY=$SECRET_KEY
SECRET_KEY=dev_secret_key_for_testing_only
JWT_SECRET_KEY=dev_jwt_secret_key_for_testing_only

# Development Mode
OSINT_USE_KEYRING=false
OSINT_TEST_MODE=false
DEBUG=true
PRODUCTION=false
ENVIRONMENT=development
ENABLE_DEV_AUTH=1

# Application Settings
LOG_LEVEL=INFO
MAX_CONCURRENT_REQUESTS=10
REQUEST_TIMEOUT=30

# Optional AI/ML API Keys (leave unset for passive/API-free operation)
# AI_MODEL_API_KEY=your_api_key_here
# OPENAI_API_KEY=your_openai_key_here

# Optional External Services (not required for basic operation)
# DATABASE_URL=postgresql://user:pass@localhost:5432/osint_db
# REDIS_URL=redis://localhost:6379
# ELASTICSEARCH_URL=http://localhost:9200

# Tor Proxy (optional)
TOR_CONTROL_PORT=9051
TOR_SOCKS_PORT=9050
EOF
        echo -e "${GREEN}✅ Created .env file with secure random secret${NC}"
        echo -e "${BLUE}ℹ️  Note: AI features disabled by default (no AI_MODEL_API_KEY set)${NC}"
    else
        echo -e "${RED}❌ .env.example not found, cannot create .env${NC}"
        exit 1
    fi
fi

# Check Python dependencies
echo -e "${BLUE}📦 Checking Python dependencies...${NC}"
if ! python3 -c "import fastapi, uvicorn, pydantic" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Installing Python dependencies...${NC}"
    pip3 install -q -r requirements.txt
    echo -e "${GREEN}✅ Python dependencies installed${NC}"
else
    echo -e "${GREEN}✅ Python dependencies OK${NC}"
fi

# Check Node.js dependencies
echo -e "${BLUE}📦 Checking Node.js dependencies...${NC}"
if [ ! -d "web/node_modules" ]; then
    echo -e "${YELLOW}⚠️  Installing Node.js dependencies...${NC}"
    cd web
    npm ci --silent
    cd ..
    echo -e "${GREEN}✅ Node.js dependencies installed${NC}"
else
    echo -e "${GREEN}✅ Node.js dependencies OK${NC}"
fi

# Create required directories
mkdir -p logs output config

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Starting Services...${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Start backend API server
echo -e "${BLUE}🚀 Starting Backend API Server...${NC}"
python3 main.py --web &
BACKEND_PID=$!
echo -e "${GREEN}   Backend PID: $BACKEND_PID${NC}"

# Wait a few seconds for backend to start
sleep 5

# Check if backend is running - try both /api/health and /health
if curl -sf http://localhost:8000/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend is running on http://localhost:8000${NC}"
    echo -e "${BLUE}   API Docs: http://localhost:8000/docs${NC}"
elif curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend is running on http://localhost:8000${NC}"
    echo -e "${BLUE}   API Docs: http://localhost:8000/docs${NC}"
else
    echo -e "${YELLOW}⚠️  Backend might still be starting...${NC}"
    echo -e "${BLUE}   Waiting additional time for initialization...${NC}"
    sleep 3
fi

# Start frontend
echo ""
echo -e "${BLUE}🎨 Starting Frontend Web Interface...${NC}"
cd web
npm run dev &
FRONTEND_PID=$!
cd ..
echo -e "${GREEN}   Frontend PID: $FRONTEND_PID${NC}"

# Wait for frontend to start
sleep 3

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  🎉 OSINT Suite is Ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}📍 Access Points:${NC}"
echo -e "   ${GREEN}Frontend:${NC} http://localhost:3000"
echo -e "   ${GREEN}Backend API:${NC} http://localhost:8000"
echo -e "   ${GREEN}API Docs:${NC} http://localhost:8000/docs"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Stopping services...${NC}"
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    # Kill any remaining processes
    pkill -P $BACKEND_PID 2>/dev/null || true
    pkill -P $FRONTEND_PID 2>/dev/null || true
    echo -e "${GREEN}✅ Services stopped${NC}"
    exit 0
}

# Trap Ctrl+C and call cleanup
trap cleanup INT TERM

# Wait for processes
wait
