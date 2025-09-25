#!/usr/bin/env python3
"""
Complete OSINT Suite Demonstration
Shows all major components working together.
"""

import sys
import os
# Add parent directory to path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from datetime import datetime

from tools.query_obfuscation import query_obfuscator
from security.result_encryption import result_encryption
from security.secrets_manager import secrets_manager

from utils.anonymity_grid import (GridNodeRole, anonymous_query,
                            initialize_anonymity_grid)
from security.audit_trail import audit_trail
from utils.doh_client import resolve_dns_sync
from security.opsec_policy import enforce_policy, policy_engine
from utils.osint_utils import OSINTUtils
# Import all major components
from utils.transport import sync_get


def print_banner():
    """Print the OSINT suite banner."""
    print("=" * 70)
    print("🕵️  AUTONOMOUS OSINT SUITE - COMPLETE DEMONSTRATION 🕵️")
    print("=" * 70)
    print("Features:")
    print("• Tor-proxied HTTP client with circuit hygiene")
    print("• DNS over HTTPS (DoH) via Tor")
    print("• Query obfuscation and anti-fingerprinting")
    print("• Secure secrets management")
    print("• Immutable audit trail with ED25519 signatures")
    print("• AES-256-GCM result encryption")
    print("• OPSEC policy engine with runtime enforcement")
    print("• Anonymity grid with query mixing")
    print("• Bellingcat-style intelligence gathering")
    print("=" * 70)
    print()


def demonstrate_basic_security():
    """Demonstrate basic security features."""
    print("🔒 BASIC SECURITY FEATURES")
    print("-" * 40)
    
    # Test Tor connectivity
    print("1. Testing Tor connectivity...")
    try:
        response = sync_get("https://check.torproject.org/api/ip")
        if response:
            data = response.json()
            print(f"   ✓ Connected via Tor: {data.get('IsTor', False)}")
            print(f"   ✓ Exit IP: {data.get('IP', 'unknown')}")
        else:
            print("   ❌ Tor connectivity test failed")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test DoH
    print("\n2. Testing DNS over HTTPS...")
    try:
        result = resolve_dns_sync("example.com", "A")
        if result and result.answers:
            print(f"   ✓ DoH resolution successful: {result.answers[0].data}")
        else:
            print("   ❌ DoH resolution failed")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test query obfuscation
    print("\n3. Testing query obfuscation...")
    try:
        stats = query_obfuscator.get_statistics()
        print(f"   ✓ Obfuscator active: {query_obfuscator.is_running}")
        print(f"   ✓ Total queries: {stats['total_queries']}")
        print(f"   ✓ Completed queries: {stats['completed_queries']}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()


def demonstrate_secrets_management():
    """Demonstrate secrets management."""
    print("🔐 SECRETS MANAGEMENT")
    print("-" * 40)
    
    try:
        # Store a test secret
        test_key = "demo_api_key_12345"
        success = secrets_manager.store_secret(
            key="demo_service",
            value=test_key
        )
        
        if success:
            print("   ✓ Secret stored successfully")
            
            # Retrieve the secret
            retrieved = secrets_manager.get_secret("demo_service")
            if retrieved and retrieved == test_key:
                print("   ✓ Secret retrieved successfully")
            else:
                print("   ❌ Secret retrieval failed")
            
            # List secrets
            secrets_list = secrets_manager.list_secrets()
            print(f"   ✓ Total secrets stored: {len(secrets_list)}")
            
            # Note: Cleanup not implemented in this demo
            print("   ✓ Test secret stored (cleanup skipped in demo)")
        else:
            print("   ❌ Failed to store secret")
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()


def demonstrate_audit_trail():
    """Demonstrate audit trail functionality."""
    print("📝 AUDIT TRAIL")
    print("-" * 40)
    
    try:
        # Log some test operations
        audit_trail.log_operation(
            operation="demo_domain_lookup",
            actor="demo_user",
            target="example.com",
            metadata={"method": "DoH", "resolver": "cloudflare"}
        )
        
        audit_trail.log_operation(
            operation="demo_http_request",
            actor="demo_user", 
            target="https://httpbin.org/ip",
            metadata={"user_agent": "OSINT-Suite/1.0"}
        )
        
        print("   ✓ Test operations logged")
        
        # Verify integrity
        verification = audit_trail.verify_chain_integrity()
        if verification['integrity_verified']:
            print("   ✓ Audit trail integrity verified")
            print(f"   ✓ Total entries: {verification['total_entries']}")
        else:
            print("   ❌ Audit trail integrity check failed")
        
        # Search operations
        recent_ops = audit_trail.search_operations(
            actor="demo_user",
            limit=5
        )
        print(f"   ✓ Found {len(recent_ops)} recent operations")
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()


def demonstrate_result_encryption():
    """Demonstrate result encryption."""
    print("🔐 RESULT ENCRYPTION")
    print("-" * 40)
    
    try:
        # Create test result
        test_result = {
            "operation": "domain_intelligence",
            "target": "example.com",
            "timestamp": datetime.now().isoformat(),
            "results": {
                "ip_addresses": ["93.184.216.34"],
                "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
                "mx_records": []
            },
            "metadata": {
                "scan_time": 2.5,
                "sources": ["DoH", "whois"]
            }
        }
        
        # Encrypt result
        encrypted_id = result_encryption.encrypt_result(
            result_data=test_result,
            description="Demo encrypted intelligence result",
            expires_hours=24
        )
        
        if encrypted_id:
            print(f"   ✓ Result encrypted: {encrypted_id}")
            
            # List encrypted results
            results_list = result_encryption.list_encrypted_results()
            print(f"   ✓ Total encrypted results: {len(results_list)}")
            
            # Decrypt result
            decrypted = result_encryption.decrypt_result(encrypted_id)
            if decrypted:
                print("   ✓ Result decrypted successfully")
                print(f"   ✓ Target: {decrypted['target']}")
            else:
                print("   ❌ Failed to decrypt result")
            
            # Clean up
            result_encryption.delete_result(encrypted_id)
            print("   ✓ Test result cleaned up")
        else:
            print("   ❌ Failed to encrypt result")
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()


def demonstrate_opsec_policies():
    """Demonstrate OPSEC policy enforcement."""
    print("🛡️  OPSEC POLICIES")
    print("-" * 40)
    
    try:
        # Test allowed operation
        result1 = enforce_policy(
            operation_type="domain_lookup",
            target="example.com",
            actor="demo_user"
        )
        
        status1 = "ALLOWED" if result1['allowed'] else "DENIED"
        print(f"   ✓ Domain lookup: {status1}")
        
        # Test blocked operation (private IP)
        result2 = enforce_policy(
            operation_type="port_scan",
            target="192.168.1.1",
            actor="demo_user"
        )
        
        status2 = "ALLOWED" if result2['allowed'] else "DENIED"
        print(f"   ✓ Private IP scan: {status2}")
        
        # Show violations
        violations = policy_engine.get_violations(limit=3)
        print(f"   ✓ Recent violations: {len(violations)}")
        
        # Show policy stats
        stats = policy_engine.get_policy_stats()
        print(f"   ✓ Total policies: {stats['total_policies']}")
        print(f"   ✓ Operations evaluated: {stats['operations_evaluated']}")
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()


def demonstrate_anonymity_grid():
    """Demonstrate anonymity grid functionality."""
    print("🕸️  ANONYMITY GRID")
    print("-" * 40)
    
    try:
        # Initialize anonymity grid
        grid = initialize_anonymity_grid(role=GridNodeRole.EXECUTOR)
        
        print("   ✓ Anonymity grid initialized")
        
        # Submit test queries
        queries = [
            ("domain_lookup", "github.com"),
            ("domain_lookup", "stackoverflow.com"),
            ("domain_lookup", "wikipedia.org")
        ]
        
        query_ids = []
        for operation, target in queries:
            query_id = grid.submit_query(
                operation_type=operation,
                target=target,
                anonymous=True
            )
            query_ids.append(query_id)
        
        print(f"   ✓ Submitted {len(queries)} anonymous queries")
        
        # Wait for processing
        time.sleep(3)
        
        # Check results
        successful = 0
        for query_id in query_ids:
            result = grid.get_query_result(query_id, timeout=5)
            if result and result.success:
                successful += 1
        
        print(f"   ✓ Processed queries: {successful}/{len(queries)}")
        
        # Show grid statistics
        stats = grid.get_grid_statistics()
        print(f"   ✓ Queries mixed: {stats['stats']['queries_mixed']}")
        print(f"   ✓ Decoys generated: {stats['stats']['decoys_generated']}")
        
        # Cleanup
        grid.stop_grid_services()
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()


def demonstrate_integrated_workflow():
    """Demonstrate an integrated OSINT workflow."""
    print("🔄 INTEGRATED WORKFLOW")
    print("-" * 40)
    print("Simulating complete OSINT investigation with all security features...")
    print()
    
    try:
        utils = OSINTUtils()
        
        # Target for investigation
        target_domain = "github.com"
        
        print(f"🎯 Target: {target_domain}")
        print()
        
        # Step 1: Domain intelligence with full security stack
        print("Step 1: Domain intelligence gathering...")
        
        # This will use:
        # - Tor proxy for anonymity
        # - OPSEC policy enforcement  
        # - Audit trail logging
        # - DoH for DNS resolution
        response = utils.make_request(
            "https://httpbin.org/get",
            headers={"X-Target": target_domain},
            operation_type="domain_intelligence",
            actor="investigator"
        )
        
        if response:
            print("   ✓ HTTP intelligence collected")
            
            # Step 2: Encrypt and store results
            intelligence_data = {
                "target": target_domain,
                "http_status": response.status_code,
                "headers": dict(response.headers),
                "timestamp": datetime.now().isoformat()
            }
            
            # Save with encryption
            if hasattr(utils, 'save_results_encrypted'):
                encrypted_id = utils.save_results_encrypted(
                    intelligence_data,
                    operation="http_intelligence",
                    target=target_domain,
                    expires_in_hours=48
                )
                if encrypted_id:
                    print(f"   ✓ Results encrypted and stored: {encrypted_id}")
        
        # Step 3: Anonymous supplementary queries
        print("\nStep 2: Anonymous supplementary intelligence...")
        
        # Use anonymity grid for additional queries
        supplementary_queries = [
            ("whois_query", target_domain),
            ("subdomain_enum", target_domain)
        ]
        
        # Initialize anonymity grid for supplementary queries
        initialize_anonymity_grid(role=GridNodeRole.CONSUMER)
        
        for operation, target in supplementary_queries:
            result = anonymous_query(
                operation_type=operation,
                target=target,
                timeout=10
            )
            
            if result and result.success:
                print(f"   ✓ {operation}: Success")
            else:
                print(f"   ❌ {operation}: Failed")
        
        # Step 4: Generate final report
        print("\nStep 3: Generating investigation report...")

        # Collect audit trail for this investigation
        recent_operations = audit_trail.search_operations(
            actor="investigator",
            limit=10
        )

        investigation_report = {
            "investigation_id": f"inv_{int(time.time())}",
            "target": target_domain,
            "start_time": datetime.now().isoformat(),
            "operations_performed": len(recent_operations),
            "security_features_used": [
                "Tor anonymization",
                "DoH DNS resolution",
                "OPSEC policy enforcement",
                "Audit trail logging",
                "Result encryption",
                "Anonymity grid mixing"
            ],
            "status": "completed"
        }
        
        print("   ✓ Investigation completed successfully")
        print(f"   ✓ Operations performed:"
              f" {investigation_report['operations_performed']}")
        print(f"   ✓ Security features:"
              f" {len(investigation_report['security_features_used'])}")
        
    except Exception as e:
        print(f"   ❌ Workflow error: {e}")
    
    print()


def show_final_statistics():
    """Show final statistics from all components."""
    print("📊 FINAL STATISTICS")
    print("-" * 40)
    
    try:
        # Audit trail stats
        verification = audit_trail.verify_chain_integrity()
        print(f"Audit Entries: {verification.get('total_entries', 0)}")
        
        # Policy engine stats
        policy_stats = policy_engine.get_policy_stats()
        print(f"Policy Evaluations: {policy_stats.get('operations_evaluated', 0)}")
        print(f"Policy Violations: {policy_stats.get('total_violations', 0)}")
        
        # Secrets manager stats
        secrets_stats = secrets_manager.get_statistics()
        print(f"Stored Secrets: {secrets_stats.get('total_secrets', 0)}")
        
        # Query obfuscation stats
        obfuscation_stats = query_obfuscator.get_statistics()
        print(f"Obfuscated Queries: {obfuscation_stats.get('total_queries', 0)}")
        print(f"Completed Queries: {obfuscation_stats.get('completed_queries', 0)}")
        
        # Encryption stats
        encrypted_results = result_encryption.list_encrypted_results()
        print(f"Encrypted Results: {len(encrypted_results)}")
        
    except Exception as e:
        print(f"Statistics error: {e}")
    
    print()


def main():
    """Run the complete demonstration."""
    print_banner()
    
    try:
        print("🚀 Starting comprehensive OSINT suite demonstration...\n")
        
        # Run all demonstrations
        demonstrate_basic_security()
        time.sleep(1)
        
        demonstrate_secrets_management()
        time.sleep(1)
        
        demonstrate_audit_trail()
        time.sleep(1)
        
        demonstrate_result_encryption()
        time.sleep(1)
        
        demonstrate_opsec_policies()
        time.sleep(1)
        
        demonstrate_anonymity_grid()
        time.sleep(1)
        
        demonstrate_integrated_workflow()
        time.sleep(1)
        
        show_final_statistics()
        
        print("=" * 70)
        print("✅ DEMONSTRATION COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        print()
        print("🎓 What you've seen:")
        print("• Complete autonomous OSINT suite with enterprise-grade security")
        print("• All traffic routed through Tor for anonymity")
        print("• Cryptographic audit trails and result encryption")
        print("• Runtime policy enforcement and violation tracking")
        print("• Query obfuscation and anonymity mixing")
        print("• Production-ready CLI tools and APIs")
        print()
        print("🔧 Ready for operational use!")
        print("   Run individual CLI tools for specific operations")
        print("   Integrate modules into your existing workflows")
        print("   Customize policies and configurations as needed")
        print()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Demonstration failed: {e}")
    finally:
        print("🧹 Cleaning up...")


if __name__ == "__main__":
    main()