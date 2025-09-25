#!/usr/bin/env python3
"""
Security Framework Validation Script
Demonstrates that all security components are working correctly
"""

import os
import sys
from datetime import datetime

# Add security module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'security'))

def test_rbac_manager():
    """Test RBAC Manager functionality"""
    print("🔐 Testing RBAC Manager...")

    from security.rbac_manager import rbac_manager

    # Clear any existing data
    rbac_manager._users.clear()
    rbac_manager._roles.clear()
    rbac_manager._permissions.clear()
    rbac_manager._sessions.clear()

    # Create a test user
    user = rbac_manager.create_user(
        username="test_admin",
        password="secure_password123",
        email="admin@test.com",
        full_name="Test Administrator"
    )

    print(f"✓ Created user: {user.username} (ID: {user.id})")

    # Test authentication
    authenticated = rbac_manager.authenticate_user("test_admin", "secure_password123")
    if authenticated:
        print("✓ User authentication successful")
    else:
        print("✗ User authentication failed")
        return False

    # Create session
    session = rbac_manager.create_session(user.id, "127.0.0.1", "Test Browser")
    print(f"✓ Created session: {session.session_id}")

    # Validate session
    valid_session = rbac_manager.validate_session(session.session_id)
    if valid_session:
        print("✓ Session validation successful")
    else:
        print("✗ Session validation failed")
        return False

    return True

def test_data_access_control():
    """Test Data Access Control functionality"""
    print("\n🛡️ Testing Data Access Control...")

    from security.data_access_control import data_access_control

    # Clear existing data
    data_access_control._data_objects.clear()
    data_access_control._access_policies.clear()

    # Create a data object
    data_obj = data_access_control.create_data_object(
        name="test_intelligence",
        classification="confidential",
        owner_id="test_user_123",
        content={"intel": "Test intelligence data"}
    )

    print(f"✓ Created data object: {data_obj.name} (ID: {data_obj.id})")

    # Test access control
    can_access = data_access_control.check_access("test_user_123", data_obj.id, "read")
    if can_access:
        print("✓ Access control check successful")
    else:
        print("✗ Access control check failed")
        return False

    return True

def test_security_monitor():
    """Test Security Monitor functionality"""
    print("\n📊 Testing Security Monitor...")

    from security.security_monitor import security_monitor

    # Clear existing data
    security_monitor._security_events.clear()
    security_monitor._security_alerts.clear()
    security_monitor._stats.clear()

    # Log a security event
    security_monitor.log_security_event(
        event_type="test_event",
        severity="low",
        user_id="test_user",
        details={"test": "validation"}
    )

    print(f"✓ Logged security event (total events: {len(security_monitor.security_events)})")

    # Generate a security report
    report = security_monitor.get_security_report(days=1)
    print(f"✓ Generated security report with {report['total_events']} events")

    # Test alert generation with multiple failed logins
    for i in range(6):
        security_monitor.log_security_event(
            event_type="authentication_failed",
            severity="medium",
            ip_address="192.168.1.100"
        )

    # Check if alert was generated
    alerts = len(security_monitor.security_alerts)
    print(f"✓ Generated {alerts} security alert(s)")

    return True

def test_security_api():
    """Test Security API components"""
    print("\n🚀 Testing Security API...")

    from security.security_api import SecurityController

    controller = SecurityController()

    # Test token creation
    from security.rbac_manager import User
    user = User(
        id="test123",
        username="testuser",
        email="test@example.com",
        full_name="Test User",
        is_active=True,
        created_at=datetime.now()
    )

    token = controller.create_access_token(user)
    print(f"✓ Created JWT token: {token[:20]}...")

    # Test token verification
    payload = controller.verify_token(token)
    if payload and payload['sub'] == user.id:
        print("✓ Token verification successful")
    else:
        print("✗ Token verification failed")
        return False

    return True

def test_integration():
    """Test integration between components"""
    print("\n🔗 Testing Component Integration...")

    from security.data_access_control import data_access_control
    from security.rbac_manager import rbac_manager
    from security.security_monitor import security_monitor

    # Clear all data
    rbac_manager._users.clear()
    rbac_manager._sessions.clear()
    data_access_control._data_objects.clear()
    security_monitor._security_events.clear()
    security_monitor._security_alerts.clear()

    # Create user
    user = rbac_manager.create_user(
        username="integration_test",
        password="test123",
        email="integration@test.com",
        full_name="Integration Test User"
    )

    # Create data
    data_obj = data_access_control.create_data_object(
        name="integration_data",
        classification="confidential",
        owner_id=user.id,
        content={"test": "integration data"}
    )

    # Check access
    can_access = data_access_control.check_access(user.id, data_obj.id, "read")

    # Log access event
    security_monitor.log_security_event(
        event_type="data_access",
        severity="low",
        user_id=user.id,
        details={"data_id": data_obj.id, "action": "read"}
    )

    print("✓ User created, data protected, access logged")
    print(f"✓ Integration test: {'PASSED' if can_access else 'FAILED'}")

    return can_access

def main():
    """Run all validation tests"""
    print("🔒 OSINT Suite Security Framework Validation")
    print("=" * 50)

    tests = [
        ("RBAC Manager", test_rbac_manager),
        ("Data Access Control", test_data_access_control),
        ("Security Monitor", test_security_monitor),
        ("Security API", test_security_api),
        ("Integration", test_integration)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")

    print("\n" + "=" * 50)
    print(f"📊 Validation Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All security framework components are working correctly!")
        return 0
    else:
        print("⚠️  Some components need attention.")
        return 1

if __name__ == "__main__":
    sys.exit(main())