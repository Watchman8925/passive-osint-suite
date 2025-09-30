#!/usr/bin/env python3
"""
Repo Cleanup Analyzer

Finds large files, duplicate files by content hash, and common generated artifacts.
Emits a report to stdout and writes details to output/repo_cleanup_report.json.

Safe by default: it NEVER deletes anything. Use the report to remove files manually.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
IGNORE_DIRS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "venv",
    ".venv",
    "env",
    "node_modules",
    "web/dist",
    ".parcel-cache",
    "output",
    "logs",
}

GENERATED_PATTERNS = (
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".cache",
    ".coverage",
)

MAX_SCAN_BYTES = 1024 * 1024 * 1024  # 1 GB guardrail
LARGE_FILE_THRESHOLD = 25 * 1024 * 1024  # 25 MB


def iter_files(root: Path) -> List[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # prune ignored dirs
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            yield p


def file_hash(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        total = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SCAN_BYTES:
                raise RuntimeError(f"Aborting hash of {path} > {MAX_SCAN_BYTES} bytes")
            h.update(chunk)
    return h.hexdigest()


def human(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def analyze_repo(root: Path) -> Dict:
    sizes: List[Tuple[int, str]] = []
    hashes: Dict[str, List[str]] = {}
    generated: List[str] = []

    for p in iter_files(root):
        try:
            st = p.stat()
        except FileNotFoundError:
            continue
        size = st.st_size
        sizes.append((size, str(p.relative_to(root))))

        # Duplicate detection for moderately sized files (< 250MB)
        if size < 250 * 1024 * 1024:
            try:
                h = file_hash(p)
            except Exception:
                h = "<error>"
            hashes.setdefault(h, []).append(str(p.relative_to(root)))

        # Generated artifacts heuristic
        for pat in GENERATED_PATTERNS:
            if p.name.endswith(pat):
                generated.append(str(p.relative_to(root)))
                break

    sizes.sort(reverse=True)
    top_30 = sizes[:30]

    dups = {
        h: paths for h, paths in hashes.items() if h != "<error>" and len(paths) > 1
    }

    report = {
        "top_largest": [
            {"path": path, "size": bytes, "size_h": human(bytes)}
            for bytes, path in top_30
        ],
        "duplicates": dups,
        "generated_candidates": generated,
        "thresholds": {
            "large_file_mb": LARGE_FILE_THRESHOLD // (1024 * 1024),
            "max_scan_bytes": MAX_SCAN_BYTES,
        },
    }
    return report


def main() -> int:
    report = analyze_repo(ROOT)
    out_dir = ROOT / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "repo_cleanup_report.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\nTop 30 largest files:\n----------------------")
    for item in report["top_largest"]:
        print(f"{item['size_h']:>9}  {item['path']}")

    dup_count = sum(len(v) for v in report["duplicates"].values())
    print(
        f"\nDuplicate groups: {len(report['duplicates'])}  (files involved: {dup_count})"
    )

    print("\nGenerated artifact candidates (heuristic):")
    for p in report["generated_candidates"][:50]:
        print(f" - {p}")

    print(f"\nFull report written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
