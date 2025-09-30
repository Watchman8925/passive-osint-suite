#!/usr/bin/env python3
"""
Demonstration of the audit trail system.
Shows cryptographic audit logging in action.
"""

import asyncio
import time
from datetime import datetime
from pathlib import Path

from security.audit_trail import AuditTrail, audit_operation


async def demo_basic_audit():
    """Demonstrate basic audit trail functionality."""
    print("🔐 Audit Trail System Demo")
    print("=" * 50)

    # Initialize audit trail
    trail = AuditTrail(audit_dir="demo_audit", max_entries_per_file=5)

    print(f"✓ Initialized audit trail at: {trail.audit_dir}")
    print(f"✓ Signing key: {trail.key_file}")

    # Log some operations
    print("\n📝 Logging operations...")

    operations = [
        (
            "domain_lookup",
            "user",
            "example.com",
            {"resolver": "doh", "records": ["A", "MX"]},
        ),
        ("ip_lookup", "user", "8.8.8.8", {"source": "whois", "timeout": 10}),
        (
            "file_analysis",
            "media_forensics",
            "suspect.jpg",
            {"type": "exif", "size": 1024000},
        ),
        (
            "port_scan",
            "network_intel",
            "192.168.1.1",
            {"ports": [22, 80, 443], "method": "passive"},
        ),
        (
            "certificate_check",
            "ssl_analyzer",
            "badsite.com",
            {"protocol": "https", "chain_depth": 3},
        ),
        (
            "subdomain_enum",
            "bellingcat_toolkit",
            "target.com",
            {"method": "passive", "sources": ["crt.sh"]},
        ),
    ]

    session_id = f"demo_{int(time.time())}"

    for operation, actor, target, metadata in operations:
        entry_id = trail.log_operation(
            operation=operation,
            actor=actor,
            target=target,
            metadata=metadata,
            session_id=session_id,
        )
        print(f"  ✓ Logged {operation} -> {entry_id}")
        time.sleep(0.1)  # Small delay for demonstration

    return trail, session_id


def demo_verification(trail):
    """Demonstrate audit trail verification."""
    print("\n🔍 Verifying audit trail integrity...")

    # Verify current log file
    results = trail.verify_chain_integrity()

    print(f"File: {results['file']}")
    print(f"Total entries: {results['total_entries']}")
    print(f"Verified signatures: {results['verified_entries']}")
    print(f"Signature failures: {results['signature_failures']}")
    print(f"Hash chain failures: {results['hash_chain_failures']}")

    if results["integrity_verified"]:
        print("✅ Audit trail integrity VERIFIED")
    else:
        print("❌ Audit trail integrity FAILED")
        for error in results["errors"]:
            print(f"  - {error}")

    return results["integrity_verified"]


def demo_search(trail, session_id):
    """Demonstrate searching audit entries."""
    print("\n🔎 Searching audit entries...")

    # Search all entries from our demo session
    entries = trail.search_entries(session_id=session_id)
    print(f"Found {len(entries)} entries from session {session_id}")

    # Search for specific operations
    domain_lookups = trail.search_entries(operation="domain_lookup")
    print(f"Found {len(domain_lookups)} domain lookup operations")

    # Search by actor
    user_operations = trail.search_entries(actor="user")
    print(f"Found {len(user_operations)} operations by user")

    # Show a sample entry
    if entries:
        print("\nSample audit entry:")
        sample = entries[0]
        print(f"  Timestamp: {sample['timestamp']}")
        print(f"  Operation: {sample['operation']}")
        print(f"  Actor: {sample['actor']}")
        print(f"  Target: {sample['target']}")
        print(f"  Signature: {sample['signature'][:20]}...")

    return entries


def demo_decorator():
    """Demonstrate automatic audit logging with decorator."""
    print("\n🎭 Decorator-based audit logging...")

    @audit_operation("crypto_analysis", "demo_user")
    def analyze_bitcoin_address(address):
        """Simulate bitcoin address analysis."""
        time.sleep(0.1)  # Simulate processing
        return {"address": address, "type": "P2PKH", "valid": True, "transactions": 42}

    @audit_operation("social_media_lookup", "demo_user")
    def search_username(username):
        """Simulate social media username search."""
        time.sleep(0.1)  # Simulate processing
        platforms = ["twitter", "instagram", "facebook", "linkedin"]
        return {
            "username": username,
            "found_on": platforms[:2],  # Simulate finding on first 2 platforms
            "confidence": 0.85,
        }

    # These function calls will be automatically audited
    btc_result = analyze_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    social_result = search_username("suspicious_user123")

    print(
        f"✓ Bitcoin analysis: {btc_result['address']} -> "
        f"{btc_result['transactions']} tx"
    )
    username = social_result["username"]
    platforms = len(social_result["found_on"])
    print(f"✓ Social media search: {username} -> {platforms} platforms")


def demo_export(trail):
    """Demonstrate audit trail export."""
    print("\n📤 Exporting audit trail...")

    # Export to JSON
    json_file = "demo_audit_export.json"
    success = trail.export_audit_trail(json_file, "json")

    if success:
        print(f"✓ Exported to {json_file}")

        # Show file size
        file_size = Path(json_file).stat().st_size
        print(f"  File size: {file_size:,} bytes")

        # Clean up
        Path(json_file).unlink()
        print("  ✓ Cleaned up export file")
    else:
        print("❌ Export failed")


def demo_tampering_detection(trail):
    """Demonstrate tampering detection."""
    print("\n🚨 Tampering detection demo...")

    # Find the current log file
    log_files = sorted(trail.audit_dir.glob("audit_*.jsonl"))
    if not log_files:
        print("No log files found for tampering demo")
        return

    current_log = log_files[-1]

    # Read original content
    with open(current_log, "r") as f:
        original_lines = f.readlines()

    print(f"Original file has {len(original_lines)} entries")

    # Verify original integrity
    original_verification = trail.verify_chain_integrity(current_log)
    is_verified = original_verification["integrity_verified"]
    status = "✅ VERIFIED" if is_verified else "❌ FAILED"
    print(f"Original integrity: {status}")

    # Simulate tampering by modifying a line
    if len(original_lines) > 1:
        print("\n🔧 Simulating tampering...")

        # Create a backup and modify the file
        backup_file = current_log.with_suffix(".jsonl.backup")
        with open(backup_file, "w") as f:
            f.writelines(original_lines)

        # Modify the second line (change target)
        import json

        modified_lines = original_lines.copy()
        if len(modified_lines) > 1:
            try:
                entry = json.loads(modified_lines[1])
                entry["target"] = "TAMPERED_TARGET.com"  # Tamper with target
                modified_lines[1] = json.dumps(entry) + "\n"

                # Write tampered file
                with open(current_log, "w") as f:
                    f.writelines(modified_lines)

                print("✓ File tampered (modified target in second entry)")

                # Verify tampered file
                tampered_verification = trail.verify_chain_integrity(current_log)
                tampered_verified = tampered_verification["integrity_verified"]
                tampered_status = "✅ VERIFIED" if tampered_verified else "❌ FAILED"
                print(f"Tampered integrity: {tampered_status}")

                if not tampered_verification["integrity_verified"]:
                    print("🎯 Tampering detected successfully!")
                    print("Verification errors:")
                    # Show first 3 errors
                    for error in tampered_verification["errors"][:3]:
                        print(f"  - {error}")

                # Restore original file
                with open(backup_file, "r") as f:
                    original_content = f.read()
                with open(current_log, "w") as f:
                    f.write(original_content)

                backup_file.unlink()  # Clean up backup
                print("✓ Original file restored")

            except Exception as e:
                print(f"Tampering demo failed: {e}")
                # Restore from backup if it exists
                if backup_file.exists():
                    with open(backup_file, "r") as f:
                        original_content = f.read()
                    with open(current_log, "w") as f:
                        f.write(original_content)
                    backup_file.unlink()


async def main():
    """Main demonstration function."""
    print("🚀 Starting Audit Trail Demonstration")
    print(f"Time: {datetime.now().isoformat()}")

    try:
        # Basic audit functionality
        trail, session_id = await demo_basic_audit()

        # Verification
        demo_verification(trail)

        # Search functionality
        demo_search(trail, session_id)

        # Decorator usage
        demo_decorator()

        # Export functionality
        demo_export(trail)

        # Tampering detection
        demo_tampering_detection(trail)

        print("\n✅ Demonstration completed successfully!")
        print("\nThe audit trail provides:")
        print("  🔐 Cryptographic integrity (ED25519 signatures)")
        print("  🔗 Hash chain validation")
        print("  🕵️  Tamper detection")
        print("  🔍 Searchable operations")
        print("  📁 Automatic rotation")
        print("  📤 Export capabilities")

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
