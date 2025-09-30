#!/usr/bin/env python3
"""
Command-line interface for audit trail management.
Provides tools to view, verify, and export audit logs.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from tabulate import tabulate

# Import our audit trail
try:
    from security.audit_trail import AuditTrail, audit_trail
except ImportError:
    print("Error: Could not import audit_trail module")
    sys.exit(1)


def cmd_log(args):
    """Log a new audit entry."""
    try:
        entry_id = audit_trail.log_operation(
            operation=args.operation,
            actor=args.actor or "cli_user",
            target=args.target,
            metadata=json.loads(args.metadata) if args.metadata else {},
            session_id=args.session_id,
        )
        print(f"✓ Logged audit entry: {entry_id}")
        return True
    except Exception as e:
        print(f"✗ Failed to log entry: {e}")
        return False


def cmd_verify(args):
    """Verify audit trail integrity."""
    try:
        if args.file:
            log_file = Path(args.file)
            if not log_file.exists():
                print(f"✗ Log file not found: {args.file}")
                return False
        else:
            log_file = None

        results = audit_trail.verify_chain_integrity(log_file)

        print(f"Verification Results for: {results['file']}")
        print(f"Total entries: {results['total_entries']}")
        print(f"Verified entries: {results['verified_entries']}")
        print(f"Signature failures: {results['signature_failures']}")
        print(f"Hash chain failures: {results['hash_chain_failures']}")

        if results["integrity_verified"]:
            print("✓ Audit trail integrity VERIFIED")
        else:
            print("✗ Audit trail integrity FAILED")

            if args.verbose and results["errors"]:
                print("\nErrors:")
                for error in results["errors"]:
                    print(f"  - {error}")

        return results["integrity_verified"]

    except Exception as e:
        print(f"✗ Verification failed: {e}")
        return False


def cmd_search(args):
    """Search audit entries."""
    try:
        # Parse time filters
        start_time = None
        end_time = None

        if args.start_time:
            start_time = datetime.fromisoformat(args.start_time)
        if args.end_time:
            end_time = datetime.fromisoformat(args.end_time)

        entries = audit_trail.search_entries(
            operation=args.operation,
            actor=args.actor,
            target=args.target,
            session_id=args.session_id,
            start_time=start_time,
            end_time=end_time,
            limit=args.limit,
        )

        if not entries:
            print("No matching entries found.")
            return True

        print(f"Found {len(entries)} matching entries:")

        if args.format == "json":
            print(json.dumps(entries, indent=2))
        elif args.format == "table":
            # Prepare table data
            table_data = []
            headers = ["Timestamp", "Operation", "Actor", "Target", "Session ID"]

            for entry in entries:
                table_data.append(
                    [
                        entry.get("timestamp", ""),
                        entry.get("operation", ""),
                        entry.get("actor", ""),
                        entry.get("target", ""),
                        entry.get("session_id", ""),
                    ]
                )

            print(tabulate(table_data, headers=headers, tablefmt="grid"))

        return True

    except Exception as e:
        print(f"✗ Search failed: {e}")
        return False


def cmd_export(args):
    """Export audit trail."""
    try:
        success = audit_trail.export_audit_trail(args.output, args.format)

        if success:
            print(f"✓ Audit trail exported to: {args.output}")
        else:
            print("✗ Export failed")

        return success

    except Exception as e:
        print(f"✗ Export failed: {e}")
        return False


def cmd_init(args):
    """Initialize a new audit trail."""
    try:
        # Create new audit trail with custom settings
        AuditTrail(
            audit_dir=args.audit_dir,
            key_file=args.key_file,
            auto_rotate=args.auto_rotate,
            max_entries_per_file=args.max_entries,
        )

        print(f"✓ Initialized audit trail at: {args.audit_dir}")
        print(f"  Auto-rotate: {args.auto_rotate}")
        print(f"  Max entries per file: {args.max_entries}")

        return True

    except Exception as e:
        print(f"✗ Initialization failed: {e}")
        return False


def cmd_status(args):
    """Show audit trail status."""
    try:
        audit_dir = Path(audit_trail.audit_dir)
        log_files = sorted(audit_dir.glob("audit_*.jsonl"))

        print("Audit Trail Status")
        print(f"Directory: {audit_dir}")
        print(f"Log files: {len(log_files)}")

        if log_files:
            total_entries = 0
            for log_file in log_files:
                try:
                    entries = sum(1 for _ in open(log_file))
                    total_entries += entries
                    print(f"  {log_file.name}: {entries} entries")
                except Exception:
                    print(f"  {log_file.name}: Error reading file")

            print(f"Total entries: {total_entries}")

        # Check key files
        key_file = audit_dir / "audit_signing_key.pem"
        public_key_file = audit_dir / "audit_public_key.pem"

        print(f"Signing key: {'✓' if key_file.exists() else '✗'}")
        print(f"Public key: {'✓' if public_key_file.exists() else '✗'}")

        return True

    except Exception as e:
        print(f"✗ Status check failed: {e}")
        return False


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Audit Trail Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s log --operation "domain_lookup" --target "example.com"
  %(prog)s verify --verbose
  %(prog)s search --operation "domain_lookup" --limit 10
  %(prog)s export --output audit_export.json --format json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Log command
    log_parser = subparsers.add_parser("log", help="Log a new audit entry")
    log_parser.add_argument("--operation", required=True, help="Operation type")
    log_parser.add_argument("--actor", help="Actor performing operation")
    log_parser.add_argument("--target", help="Target of operation")
    log_parser.add_argument("--metadata", help="JSON metadata")
    log_parser.add_argument("--session-id", help="Session identifier")
    log_parser.set_defaults(func=cmd_log)

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify audit trail integrity")
    verify_parser.add_argument("--file", help="Specific log file to verify")
    verify_parser.add_argument(
        "--verbose", action="store_true", help="Show detailed errors"
    )
    verify_parser.set_defaults(func=cmd_verify)

    # Search command
    search_parser = subparsers.add_parser("search", help="Search audit entries")
    search_parser.add_argument("--operation", help="Filter by operation")
    search_parser.add_argument("--actor", help="Filter by actor")
    search_parser.add_argument("--target", help="Filter by target")
    search_parser.add_argument("--session-id", help="Filter by session ID")
    search_parser.add_argument("--start-time", help="Start time (ISO format)")
    search_parser.add_argument("--end-time", help="End time (ISO format)")
    search_parser.add_argument("--limit", type=int, help="Maximum results")
    search_parser.add_argument(
        "--format", choices=["json", "table"], default="table", help="Output format"
    )
    search_parser.set_defaults(func=cmd_search)

    # Export command
    export_parser = subparsers.add_parser("export", help="Export audit trail")
    export_parser.add_argument("--output", required=True, help="Output file path")
    export_parser.add_argument(
        "--format", choices=["json", "csv"], default="json", help="Export format"
    )
    export_parser.set_defaults(func=cmd_export)

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize new audit trail")
    init_parser.add_argument(
        "--audit-dir", default="logs/audit", help="Audit directory path"
    )
    init_parser.add_argument("--key-file", help="Signing key file path")
    init_parser.add_argument(
        "--auto-rotate", type=bool, default=True, help="Enable auto-rotation"
    )
    init_parser.add_argument(
        "--max-entries", type=int, default=10000, help="Max entries per file"
    )
    init_parser.set_defaults(func=cmd_init)

    # Status command
    status_parser = subparsers.add_parser("status", help="Show audit trail status")
    status_parser.set_defaults(func=cmd_status)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    try:
        success = args.func(args)
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n✗ Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
