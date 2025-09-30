#!/usr/bin/env python3
"""
Demonstration of query obfuscation and anti-fingerprinting capabilities.
Shows how to use the enhanced OSINT suite with anonymity features.
"""

import asyncio
import logging
from datetime import datetime

from query_obfuscation import get_obfuscation_stats, query_obfuscator

from osint_utils import OSINTUtils
from transport import get_tor_status

# Configure logging to see obfuscation in action
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


async def demonstrate_obfuscation():
    """Demonstrate query obfuscation capabilities."""

    print("🔒 OSINT Suite - Query Obfuscation Demonstration")
    print("=" * 60)

    # Initialize OSINT utilities
    utils = OSINTUtils()

    # Check Tor status
    print("\n📡 Checking Tor connectivity...")
    tor_status = get_tor_status()
    if tor_status["proxy_configured"]:
        print(f"✅ Tor proxy configured: {tor_status['proxy_url']}")
        if tor_status["control_available"]:
            print("✅ Tor control available - circuit management enabled")
        else:
            print("⚠️ Tor control not available - basic proxy mode")
    else:
        print("❌ Tor not configured - anonymity compromised!")
        return

    # Validate Tor connection
    if utils.validate_tor_connection():
        print("✅ Tor connection validated")
    else:
        print("❌ Tor connection failed!")
        return

    # Start obfuscation system
    print("\n🎭 Starting query obfuscation system...")
    await query_obfuscator.start()

    # Show initial stats
    stats = get_obfuscation_stats()
    print(f"📊 Obfuscation system ready - {stats}")

    print("\n" + "=" * 60)
    print("DEMONSTRATION SCENARIOS")
    print("=" * 60)

    # Scenario 1: Single obfuscated request
    print("\n🎯 Scenario 1: Single Obfuscated Request")
    print("-" * 40)

    print("Submitting obfuscated request to example.com...")
    query_id = await query_obfuscator.submit_query(
        target="https://example.com",
        method="http",
        parameters={"timeout": 30},
        priority=1,
    )
    print(f"📝 Query submitted with ID: {query_id}")

    # Wait a moment and check stats
    await asyncio.sleep(2)
    stats = get_obfuscation_stats()
    print(f"📊 Stats after submission: {stats}")

    # Scenario 2: Batch requests with decoys
    print("\n🎯 Scenario 2: Batch Requests with Decoys")
    print("-" * 40)

    # Prepare a batch of target queries
    target_queries = [
        ("https://httpbin.org/ip", "http", {"timeout": 30}),
        ("https://httpbin.org/user-agent", "http", {"timeout": 30}),
        ("https://httpbin.org/headers", "http", {"timeout": 30}),
    ]

    print(f"Submitting batch of {len(target_queries)} queries with decoys...")
    batch_id = await query_obfuscator.submit_batch(
        queries=target_queries, priority=2, add_decoys=True
    )
    print(f"📦 Batch submitted with ID: {batch_id}")

    # Scenario 3: DNS obfuscation
    print("\n🎯 Scenario 3: DNS Resolution with Obfuscation")
    print("-" * 40)

    # Test secure DNS resolution
    domains_to_test = ["google.com", "github.com", "stackoverflow.com"]

    for domain in domains_to_test:
        print(f"Resolving {domain} securely...")
        ip = utils.get_domain_ip_secure(domain)
        if ip:
            print(f"✅ {domain} -> {ip}")
        else:
            print(f"❌ Failed to resolve {domain}")

    # Scenario 4: Mixed obfuscated operations
    print("\n🎯 Scenario 4: Mixed Operations with Timing Variation")
    print("-" * 40)

    # Submit multiple queries with different priorities and delays
    operations = [
        ("https://httpbin.org/delay/1", "http", {"timeout": 35}, 1),  # High priority
        ("https://httpbin.org/status/200", "http", {"timeout": 30}, 2),  # Medium
        ("https://httpbin.org/json", "http", {"timeout": 30}, 3),  # Low priority
    ]

    submitted_queries = []
    for url, method, params, priority in operations:
        query_id = await query_obfuscator.submit_query(
            target=url, method=method, parameters=params, priority=priority
        )
        submitted_queries.append(query_id)
        print(f"📝 Submitted {url} with priority {priority}: {query_id}")

    # Monitor execution
    print("\n⏳ Monitoring query execution...")
    for i in range(10):  # Monitor for 10 seconds
        stats = get_obfuscation_stats()
        print(
            f"📊 [{i+1:2d}s] Queries: {stats['queries_submitted']:3d} submitted, "
            f"{stats['queries_executed']:3d} executed, "
            f"{stats['decoy_queries_generated']:3d} decoys generated"
        )

        # Check individual query status
        for query_id in submitted_queries[:2]:  # Check first 2 queries
            status = query_obfuscator.get_query_status(query_id)
            if status:
                print(f"    📍 {query_id}: {status.get('status', 'unknown')}")

        await asyncio.sleep(1)

    # Final statistics
    print("\n📈 FINAL STATISTICS")
    print("-" * 40)
    final_stats = get_obfuscation_stats()

    print(f"Total queries submitted: {final_stats['queries_submitted']}")
    print(f"Total queries executed: {final_stats['queries_executed']}")
    print(f"Decoy queries generated: {final_stats['decoy_queries_generated']}")
    print(f"Batches created: {final_stats['batches_created']}")
    print(f"Batches executed: {final_stats['batches_executed']}")
    print(f"Total delay added: {final_stats['total_delay_added']:.2f}s")
    print(f"Fingerprinting events avoided: {final_stats['fingerprinting_avoided']}")

    # Calculate obfuscation ratio
    total_operations = final_stats["queries_executed"]
    if total_operations > 0:
        obfuscation_ratio = (
            final_stats["fingerprinting_avoided"] / total_operations
        ) * 100
        print(f"Obfuscation ratio: {obfuscation_ratio:.1f}% (decoy/noise queries)")

    print("\n🎭 Query Obfuscation Benefits:")
    print("   • Real queries mixed with decoy traffic")
    print("   • Randomized timing prevents pattern detection")
    print("   • Multiple resolver rotation avoids DNS fingerprinting")
    print("   • Circuit rotation provides IP address changes")
    print("   • Batch processing masks individual query intentions")

    # Stop obfuscation system
    print("\n🛑 Stopping obfuscation system...")
    await query_obfuscator.stop()
    print("✅ Demonstration complete!")


def demonstrate_sync_features():
    """Demonstrate synchronous obfuscation features."""

    print("\n🔧 SYNCHRONOUS FEATURES DEMONSTRATION")
    print("=" * 60)

    utils = OSINTUtils()

    # Test obfuscation status
    print("\n📊 Obfuscation System Status:")
    status = utils.get_obfuscation_status()
    for key, value in status.items():
        print(f"   {key}: {value}")

    # Test secure DNS resolution
    print("\n🔍 Secure DNS Resolution:")
    test_domains = ["example.com", "github.com"]

    for domain in test_domains:
        print(f"\nResolving {domain}:")

        # A record
        a_records = utils.resolve_domain_secure(domain, "A")
        if a_records:
            print(f"   A records: {a_records}")

        # IPv6 record
        ipv6 = utils.get_domain_ipv6_secure(domain)
        if ipv6:
            print(f"   AAAA record: {ipv6}")

        # MX records
        mx_records = utils.resolve_domain_secure(domain, "MX")
        if mx_records:
            print(f"   MX records: {mx_records}")


if __name__ == "__main__":
    print("🚀 Starting OSINT Suite Obfuscation Demonstration")
    print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run synchronous features first
    demonstrate_sync_features()

    # Run async demonstration
    try:
        asyncio.run(demonstrate_obfuscation())
    except KeyboardInterrupt:
        print("\n⚠️ Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        logging.exception("Demonstration failed")

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n🏁 Demonstration ended at: {end_time}")
