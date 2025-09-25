#!/bin/bash
cd "$(dirname "$0")"
source .venv/bin/activate

# Set Python path
export PYTHONPATH="$PWD:$PYTHONPATH"

# Check if arguments provided
if [ $# -eq 0 ]; then
    echo "Starting OSINT Suite in interactive mode..."
    python3 main.py
else
    echo "Starting OSINT Suite with arguments: $@"
    python3 main.py "$@"
fi
