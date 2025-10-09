#!/usr/bin/env bash
set -euo pipefail

# Run Ruff via Docker so you don't need it installed on your host.
# Usage:
#   scripts/run_ruff.sh check         # ruff check . (read-only)
#   scripts/run_ruff.sh fix           # ruff check --fix . (writes changes)
#   scripts/run_ruff.sh format        # ruff format . (writes changes)
#   scripts/run_ruff.sh format-check  # ruff format --check . (read-only)
#   scripts/run_ruff.sh <args...>     # pass arbitrary args to ruff

IMAGE="python:3.12-slim"
WORKDIR="/work"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run this script." >&2
  exit 1
fi

cmd=("check" ".")
if [[ $# -gt 0 ]]; then
  case "$1" in
    check)
      cmd=("check" ".")
      shift || true
      ;;
    fix)
      cmd=("check" "--fix" ".")
      shift || true
      ;;
    format)
      cmd=("format" ".")
      shift || true
      ;;
    format-check)
      cmd=("format" "--check" ".")
      shift || true
      ;;
    *)
      cmd=("$@")
      ;;
  esac
fi

echo "Running: ruff ${cmd[*]}"
exec docker run --rm \
  -v "$(pwd)":"${WORKDIR}" \
  -w "${WORKDIR}" \
  "${IMAGE}" \
  sh -c "pip install ruff==0.8.0 >/dev/null 2>&1 && ruff ${cmd[*]}"
