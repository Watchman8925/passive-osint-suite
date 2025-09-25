#!/bin/bash
cd "$(dirname "$0")"
source osint_env/bin/activate
python3 osint_suite.py "$@"
