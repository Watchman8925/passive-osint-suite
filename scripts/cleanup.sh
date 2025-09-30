#!/usr/bin/env bash
set -euo pipefail

# Safe cleanup script
# - Dry-run by default: shows what would be removed
# - Use --apply to actually delete
# - Only removes whitelisted caches/logs/build artifacts

APPLY=false
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=true
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Whitelist of patterns to remove safely
PATTERNS=(
  "**/__pycache__/"
  "**/.pytest_cache/"
  "**/.mypy_cache/"
  "**/.ruff_cache/"
  "**/.cache/"
  "logs/*.log"
  "output/*.tmp"
  "web/dist/"
  ".parcel-cache/"
  "dist/"
  "build/"
)

found_any=false
for pat in "${PATTERNS[@]}"; do
  mapfile -t matches < <(shopt -s globstar nullglob dotglob && eval echo $pat)
  for m in "${matches[@]}"; do
    [[ -e "$m" ]] || continue
    found_any=true
    if $APPLY; then
      echo "Removing: $m"
      rm -rf "$m"
    else
      echo "Would remove: $m"
    fi
  done
done

if ! $found_any; then
  echo "No matching artifacts found to clean."
fi

echo "Done. Use '--apply' to perform deletions."
