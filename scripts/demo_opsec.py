#!/usr/bin/env python3
"""
OPSEC Policy Engine Demonstration
Shows policy creation, enforcement, and violation handling.
"""

import time
from datetime import datetime

from opsec_policy import (OperationContext, PolicyEngine, enforce_policy,
                          policy_enforced)


def create_demo_policies():
    """Create demonstration policies."""
    print("Creating demonstration OPSEC policies...")
    
    engine = PolicyEngine()
    
    # Security-focused policy
    security_policy = {
        "policy_id": "security_opsec",
        "name": "Security OPSEC Policy",
        "description": "Security-focused operational security rules",
        "version": "1.0",
        "enabled": True,
        "metadata": {
            "author": "Security Team",
            "created": datetime.now().isoformat(),
            "priority": "high"
        },
        "rules": [
            {
                "rule_id": "block_private_ips",
                "name": "Block Private IP Scanning",
                "description": "Prevent scanning of private network ranges",
                "condition": "is_private_ip(target)",
                "action": "deny",
                "violation_level": "high",
                "enabled": True,
                "metadata": {
                    "rationale": "Private IPs may indicate internal networks"
                }
            },
            {
                "rule_id": "suspicious_domain_warning",
                "name": "Suspicious Domain Warning",
                "description": "Flag domains with suspicious characteristics",
                "condition": "is_suspicious_domain(target)",
                "action": "warn",
                "violation_level": "medium",
                "enabled": True,
                "metadata": {}
            },
            {
                "rule_id": "rate_limit_enforcement",
                "name": "Operation Rate Limiting",
                "description": "Enforce rate limits to prevent detection",
                "condition": "rate_limit_exceeded(operation_type, 50, 60)",
                "action": "delay",
                "violation_level": "low",
                "enabled": True,
                "metadata": {
                    "delay_seconds": 10
                }
            }
        ]
    }
    
    # Operational policy
    operational_policy = {
        "policy_id": "operational_opsec",
        "name": "Operational OPSEC Policy",
        "description": "Day-to-day operational security guidelines",
        "version": "1.0",
        "enabled": True,
        "metadata": {
            "author": "Operations Team",
            "created": datetime.now().isoformat(),
            "priority": "medium"
        },
        "rules": [
            {
                "rule_id": "business_hours_approval",
                "name": "After Hours Approval Required",
                "description": "Require approval for operations outside business hours",
                "condition": "not time_range_check(9, 17)",
                "action": "require_approval",
                "violation_level": "medium",
                "enabled": True,
                "metadata": {
                    "business_hours": "9 AM - 5 PM"
                }
            },
            {
                "rule_id": "session_duration_warning",
                "name": "Long Session Warning",
                "description": "Warn about sessions exceeding 4 hours",
                "condition": "session_duration(session_id, 4)",
                "action": "warn",
                "violation_level": "low",
                "enabled": True,
                "metadata": {}
            },
            {
                "rule_id": "target_frequency_check",
                "name": "Target Frequency Check",
                "description": "Monitor repeated operations on same target",
                "condition": "operation_frequency(operation_type, target, 10)",
                "action": "warn",
                "violation_level": "medium",
                "enabled": True,
                "metadata": {}
            }
        ]
    }
    
    # Create policies
    security_id = engine.create_policy(security_policy)
    operational_id = engine.create_policy(operational_policy)
    
    print(f"✓ Created security policy: {security_id}")
    print(f"✓ Created operational policy: {operational_id}")
    print()
    
    return engine


def demonstrate_policy_enforcement():
    """Demonstrate policy enforcement scenarios."""
    print("Demonstrating policy enforcement scenarios...")
    print("=" * 50)
    
    engine = create_demo_policies()
    
    # Test cases
    test_operations = [
        {
            "name": "Valid external domain lookup",
            "operation_type": "domain_lookup",
            "target": "example.com",
            "actor": "analyst1",
            "expected": "ALLOWED"
        },
        {
            "name": "Private IP scan attempt",
            "operation_type": "port_scan",
            "target": "192.168.1.1",
            "actor": "analyst2",
            "expected": "DENIED"
        },
        {
            "name": "Suspicious domain lookup",
            "operation_type": "domain_lookup",
            "target": "malicious123456.tk",
            "actor": "analyst3",
            "expected": "WARNING"
        },
        {
            "name": "Rate limited operation",
            "operation_type": "whois_lookup",
            "target": "test.com",
            "actor": "analyst4",
            "expected": "RATE_LIMITED"
        }
    ]
    
    for i, test in enumerate(test_operations, 1):
        print(f"Test {i}: {test['name']}")
        print(f"  Operation: {test['operation_type']} on {test['target']}")
        
        # Create operation context
        context = OperationContext(
            operation_type=test['operation_type'],
            target=test['target'],
            actor=test['actor'],
            session_id=f"session_{test['actor']}"
        )
        
        # If testing rate limiting, simulate multiple operations
        if test['expected'] == "RATE_LIMITED":
            print("  Simulating 55 operations to trigger rate limit...")
            for j in range(55):
                engine.evaluate_operation(context)
        
        # Evaluate operation
        result = engine.evaluate_operation(context)
        
        print(f"  Result: {'ALLOWED' if result['allowed'] else 'DENIED'}")
        
        if result['actions']:
            print(f"  Actions: {', '.join(result['actions'])}")
        
        if result['warnings']:
            print(f"  Warnings: {', '.join(result['warnings'])}")
        
        if result['delays']:
            total_delay = sum(result['delays'])
            print(f"  Delays: {total_delay} seconds total")
        
        if result['requires_approval']:
            print("  Requires: Manual approval")
        
        if result['violations']:
            print(f"  Violations: {len(result['violations'])} recorded")
        
        print()
    
    # Show violation summary
    violations = engine.get_violations()
    print(f"Total violations recorded: {len(violations)}")
    
    for violation in violations[-3:]:  # Show last 3 violations
        print(f"  - {violation.violation_level.value.upper()}: {violation.message}")
    
    print()


def demonstrate_decorator_usage():
    """Demonstrate using the policy enforcement decorator."""
    print("Demonstrating @policy_enforced decorator...")
    print("=" * 50)
    
    # Create a demo function with policy enforcement
    @policy_enforced(operation_type="dns_lookup", actor="decorator_demo")
    def lookup_domain(domain):
        """Demo function that performs DNS lookup."""
        print(f"  Performing DNS lookup for: {domain}")
        return f"DNS result for {domain}"
    
    # Test the decorated function
    test_domains = [
        "google.com",        # Should work
        "192.168.1.1",      # Should be blocked (private IP)
        "suspicious123.tk"   # Should generate warning
    ]
    
    for domain in test_domains:
        print(f"Testing domain: {domain}")
        try:
            result = lookup_domain(domain)
            print(f"  Success: {result}")
        except PermissionError as e:
            print(f"  Blocked: {e}")
        except Exception as e:
            print(f"  Error: {e}")
        print()


def demonstrate_policy_management():
    """Demonstrate policy management operations."""
    print("Demonstrating policy management...")
    print("=" * 50)
    
    engine = PolicyEngine()
    
    # Show current policies
    print(f"Current policies: {len(engine.policies)}")
    for policy_id, policy in engine.policies.items():
        status = "ENABLED" if policy.enabled else "DISABLED"
        print(f"  - {policy.name} ({policy_id}): {status}")
    print()
    
    # Show statistics
    stats = engine.get_policy_stats()
    print("Policy Engine Statistics:")
    print(f"  Total Policies: {stats['total_policies']}")
    print(f"  Enabled Policies: {stats['enabled_policies']}")
    print(f"  Operations Evaluated: {stats['operations_evaluated']}")
    print(f"  Total Violations: {stats['total_violations']}")
    print(f"  Unresolved Violations: {stats['unresolved_violations']}")
    print()
    
    # Show violations by level
    print("Violations by Level:")
    for level, count in stats['violations_by_level'].items():
        if count > 0:
            print(f"  {level.upper()}: {count}")
    print()


def demonstrate_real_world_scenario():
    """Demonstrate a realistic OSINT investigation scenario."""
    print("Demonstrating real-world OSINT investigation scenario...")
    print("=" * 50)
    
    print("Scenario: Investigating suspicious domain 'phishing-example.tk'")
    print()
    
    # Investigation steps
    investigation_steps = [
        ("domain_lookup", "phishing-example.tk"),
        ("whois_lookup", "phishing-example.tk"),
        ("subdomain_enum", "phishing-example.tk"),
        ("port_scan", "203.0.113.1"),  # Example IP
        ("ssl_cert_check", "phishing-example.tk"),
        ("email_harvest", "phishing-example.tk"),
        ("social_media_search", "phishing-example.tk")
    ]
    
    session_id = f"investigation_{int(time.time())}"
    
    for step_num, (operation, target) in enumerate(investigation_steps, 1):
        print(f"Step {step_num}: {operation} on {target}")
        
        # Check policy before operation
        result = enforce_policy(
            operation_type=operation,
            target=target,
            actor="investigator",
            session_id=session_id
        )
        
        if result['allowed']:
            print("  ✓ Operation allowed")
            
            # Simulate operation delay
            if result['delays']:
                delay = sum(result['delays'])
                print(f"  ⏱ Policy-enforced delay: {delay} seconds")
                time.sleep(min(delay, 2))  # Cap demo delay at 2 seconds
            
            # Show warnings
            for warning in result['warnings']:
                print(f"  ⚠ {warning}")
            
            print(f"  📊 Executing {operation}...")
            time.sleep(0.5)  # Simulate operation time
            print(f"  ✅ {operation} completed")
            
        else:
            print(f"  ❌ Operation denied: {', '.join(result['actions'])}")
        
        print()
    
    print("Investigation completed!")
    
    # Show final violation summary
    engine = PolicyEngine()
    recent_violations = engine.get_violations(limit=5)
    
    if recent_violations:
        print(f"\nViolations during investigation: {len(recent_violations)}")
        for violation in recent_violations:
            level_icon = {"low": "ℹ", "medium": "⚠", "high": "❗", "critical": "🚨"}
            icon = level_icon.get(violation.violation_level.value, "❓")
            print(f"  {icon} {violation.message}")


def main():
    """Run all demonstrations."""
    print("OPSEC Policy Engine Demonstration")
    print("=" * 60)
    print()
    
    try:
        # Run demonstrations
        demonstrate_policy_enforcement()
        time.sleep(1)
        
        demonstrate_decorator_usage()
        time.sleep(1)
        
        demonstrate_policy_management()
        time.sleep(1)
        
        demonstrate_real_world_scenario()
        
        print("\n" + "=" * 60)
        print("Demonstration completed successfully!")
        print("\nTo explore further:")
        print("1. Run 'python opsec_cli.py list' to see policies")
        print("2. Run 'python opsec_cli.py violations' to see violations")
        print("3. Run 'python opsec_cli.py sample' to create a sample policy")
        print("4. Integrate policy enforcement into your OSINT tools")
        
    except KeyboardInterrupt:
        print("\nDemonstration interrupted.")
    except Exception as e:
        print(f"\nError during demonstration: {e}")


if __name__ == "__main__":
    main()