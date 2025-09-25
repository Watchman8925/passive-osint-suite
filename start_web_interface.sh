#!/bin/bash
cd "$(dirname "$0")"

# Start backend API
echo "Starting backend API..."
source .venv/bin/activate
export PYTHONPATH="$PWD:$PYTHONPATH"
python3 main.py --web &
API_PID=$!

# Start frontend
echo "Starting web interface..."
cd web
npm run dev &
WEB_PID=$!

echo "OSINT Suite web interface starting..."
echo "Backend API: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for interrupt
trap "echo 'Stopping services...'; kill $API_PID $WEB_PID 2>/dev/null; exit" INT
wait
