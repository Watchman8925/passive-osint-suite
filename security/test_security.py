"""
Security Framework Test Suite
Comprehensive tests for RBAC, data access control, monitoring, and API integration
"""

import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import jwt

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security.data_access_control import DataObject, data_access_control
from security.rbac_manager import User, rbac_manager
from security.security_api import SecurityController
from security.security_monitor import security_monitor


class TestRBACManager(unittest.TestCase):
    """Test RBAC Manager functionality"""

    def setUp(self):
        """Set up test fixtures"""
        # Clear existing data
        rbac_manager.users.clear()
        rbac_manager.roles.clear()
        rbac_manager.permissions.clear()
        rbac_manager.sessions.clear()

        # Setup test roles and permissions
        rbac_manager.add_role("admin", ["users:*", "security:*", "data:*"])
        rbac_manager.add_role("analyst", ["data:read", "intelligence:read"])
        rbac_manager.add_role("user", ["data:read"])

    def test_user_creation(self):
        """Test user creation"""
        user = rbac_manager.create_user(
            username="testuser",
            password="testpass123",
            email="test@example.com",
            full_name="Test User",
            role="user"
        )

        self.assertIsNotNone(user)
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.role, "user")
        self.assertTrue(user.is_active)

    def test_user_authentication(self):
        """Test user authentication"""
        # Create user
        user = rbac_manager.create_user(
            username="testuser",
            password="testpass123",
            email="test@example.com",
            full_name="Test User",
            role="user"
        )

        # Test successful authentication
        authenticated = rbac_manager.authenticate_user("testuser", "testpass123")
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.id, user.id)

        # Test failed authentication
        failed = rbac_manager.authenticate_user("testuser", "wrongpass")
        self.assertIsNone(failed)

    def test_permission_checking(self):
        """Test permission checking"""
        # Create admin user
        admin = rbac_manager.create_user(
            username="admin",
            password="admin123",
            email="admin@example.com",
            full_name="Admin User",
            role="admin"
        )

        # Create regular user
        user = rbac_manager.create_user(
            username="regular",
            password="user123",
            email="user@example.com",
            full_name="Regular User",
            role="user"
        )

        # Test admin permissions
        self.assertTrue(rbac_manager.check_permission(admin.id, "users", "create"))
        self.assertTrue(rbac_manager.check_permission(admin.id, "security", "read"))

        # Test user permissions
        self.assertTrue(rbac_manager.check_permission(user.id, "data", "read"))
        self.assertFalse(rbac_manager.check_permission(user.id, "users", "create"))

    def test_session_management(self):
        """Test session management"""
        user = rbac_manager.create_user(
            username="sessionuser",
            password="pass123",
            email="session@example.com",
            full_name="Session User",
            role="user"
        )

        # Create session
        session = rbac_manager.create_session(user.id, "127.0.0.1", "Test Agent")
        self.assertIsNotNone(session)
        self.assertEqual(session.user_id, user.id)

        # Validate session
        valid_session = rbac_manager.validate_session(session.session_id)
        self.assertIsNotNone(valid_session)

        # Invalidate session
        rbac_manager.invalidate_session(session.session_id)
        invalid_session = rbac_manager.validate_session(session.session_id)
        self.assertIsNone(invalid_session)

class TestDataAccessControl(unittest.TestCase):
    """Test Data Access Control functionality"""

    def setUp(self):
        """Set up test fixtures"""
        # Clear existing data
        data_access_control.data_objects.clear()
        data_access_control.access_policies.clear()

    def test_data_classification(self):
        """Test data classification"""
        # Create data object
        data_obj = data_access_control.create_data_object(
            name="test_intelligence",
            data_type="intelligence_report",
            classification="confidential",
            owner_id="user123",
            content={"report": "Test report content"}
        )

        self.assertIsNotNone(data_obj)
        self.assertEqual(data_obj.classification, "confidential")
        self.assertEqual(data_obj.owner_id, "user123")

    def test_access_control(self):
        """Test access control enforcement"""
        # Create data object
        data_obj = data_access_control.create_data_object(
            name="secret_data",
            data_type="intelligence",
            classification="secret",
            owner_id="owner123",
            content={"secret": "classified information"}
        )

        # Test owner access
        can_access = data_access_control.check_access("owner123", data_obj.id, "read")
        self.assertTrue(can_access)

        # Test unauthorized access
        can_access_unauth = data_access_control.check_access("hacker123", data_obj.id, "read")
        self.assertFalse(can_access_unauth)

    def test_data_retention(self):
        """Test data retention policies"""
        # Create data object with retention policy
        past_date = datetime.now() - timedelta(days=100)
        data_obj = DataObject(
            id="old_data",
            name="old_intelligence",
            data_type="intelligence",
            classification="public",
            owner_id="user123",
            created_at=past_date,
            retention_days=30,
            content={"old": "data"}
        )
        data_access_control.data_objects[data_obj.id] = data_obj

        # Apply retention
        data_access_control.apply_data_retention()

        # Check if old data was removed
        self.assertNotIn("old_data", data_access_control.data_objects)

class TestSecurityMonitor(unittest.TestCase):
    """Test Security Monitor functionality"""

    def setUp(self):
        """Set up test fixtures"""
        # Clear existing data
        security_monitor.security_events.clear()
        security_monitor.security_alerts.clear()
        security_monitor.stats.clear()

    def test_security_event_logging(self):
        """Test security event logging"""
        # Log security event
        security_monitor.log_security_event(
            event_type="test_event",
            severity="medium",
            user_id="user123",
            details={"test": "data"}
        )

        # Check event was logged
        self.assertEqual(len(security_monitor.security_events), 1)
        event = security_monitor.security_events[0]
        self.assertEqual(event.event_type, "test_event")
        self.assertEqual(event.severity, "medium")
        self.assertEqual(event.user_id, "user123")

    def test_security_alert_generation(self):
        """Test security alert generation"""
        # Log multiple failed login events
        for i in range(6):
            security_monitor.log_security_event(
                event_type="authentication_failed",
                severity="medium",
                ip_address="192.168.1.100",
                details={"attempt": i}
            )

        # Check for alert generation
        security_monitor._check_alert_conditions()

        # Should have generated an alert for multiple failed logins
        self.assertTrue(len(security_monitor.security_alerts) > 0)
        alert = security_monitor.security_alerts[0]
        self.assertEqual(alert.alert_type, "multiple_failed_logins")

    def test_security_report_generation(self):
        """Test security report generation"""
        # Log some events
        security_monitor.log_security_event("login_success", "low", user_id="user1")
        security_monitor.log_security_event("access_denied", "medium", user_id="user2")
        security_monitor.log_security_event("data_export", "high", user_id="user3")

        # Generate report
        report = security_monitor.get_security_report(days=1)

        # Check report structure
        self.assertIn("total_events", report)
        self.assertIn("events_by_type", report)
        self.assertIn("risk_assessment", report)
        self.assertEqual(report["total_events"], 3)

class TestSecurityAPI(unittest.TestCase):
    """Test Security API functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.controller = SecurityController()

    def test_token_creation_and_verification(self):
        """Test JWT token creation and verification"""
        # Create mock user
        user = User(
            id="test123",
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role="user",
            is_active=True,
            created_at=datetime.now(),
            last_login=None
        )

        # Create token
        token = self.controller.create_access_token(user)
        self.assertIsNotNone(token)

        # Verify token
        payload = self.controller.verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], user.id)
        self.assertEqual(payload["username"], user.username)

    def test_expired_token_verification(self):
        """Test expired token verification"""
        # Create token that expires immediately
        expire = datetime.utcnow() - timedelta(hours=1)
        to_encode = {
            "sub": "test123",
            "exp": expire,
            "type": "access"
        }

        with patch('security.security_api.JWT_SECRET', 'test_secret'):
            token = jwt.encode(to_encode, 'test_secret', algorithm='HS256')

            # Verify should return None for expired token
            payload = self.controller.verify_token(token)
            self.assertIsNone(payload)

class TestSecurityIntegration(unittest.TestCase):
    """Test security components integration"""

    def setUp(self):
        """Set up test fixtures"""
        # Clear all data
        rbac_manager.users.clear()
        rbac_manager.sessions.clear()
        data_access_control.data_objects.clear()
        security_monitor.security_events.clear()
        security_monitor.security_alerts.clear()

    def test_complete_user_workflow(self):
        """Test complete user workflow with security"""
        # 1. Create user
        user = rbac_manager.create_user(
            username="workflow_user",
            password="securepass123",
            email="workflow@example.com",
            full_name="Workflow User",
            role="analyst"
        )

        # 2. Authenticate user
        authenticated = rbac_manager.authenticate_user("workflow_user", "securepass123")
        self.assertIsNotNone(authenticated)

        # 3. Create session
        session = rbac_manager.create_session(user.id, "127.0.0.1", "Test Browser")
        self.assertIsNotNone(session)

        # 4. Create data object
        data_obj = data_access_control.create_data_object(
            name="workflow_intelligence",
            data_type="intelligence",
            classification="confidential",
            owner_id=user.id,
            content={"intel": "Test intelligence data"}
        )

        # 5. Check access permissions
        can_read = data_access_control.check_access(user.id, data_obj.id, "read")
        self.assertTrue(can_read)

        # 6. Log security event
        security_monitor.log_security_event(
            "data_access",
            severity="low",
            user_id=user.id,
            details={"data_id": data_obj.id, "action": "read"}
        )

        # 7. Verify event was logged
        self.assertEqual(len(security_monitor.security_events), 1)

    def test_security_incident_response(self):
        """Test security incident response workflow"""
        # 1. Create suspicious activity
        for i in range(10):
            security_monitor.log_security_event(
                "access_denied",
                severity="medium",
                ip_address="192.168.1.100",
                details={"resource": "sensitive_data", "attempt": i}
            )

        # 2. Check for alerts
        security_monitor._check_alert_conditions()

        # 3. Verify alert was created
        self.assertTrue(len(security_monitor.security_alerts) > 0)

        # 4. Generate security report
        report = security_monitor.get_security_report(days=1)

        # 5. Verify report contains incident information
        self.assertIn("suspicious_data_access", report["events_by_type"])

class TestSecurityConfiguration(unittest.TestCase):
    """Test security configuration and persistence"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_security_config.json")

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_monitor_configuration_save_load(self):
        """Test security monitor configuration persistence"""
        # Create monitor with custom config
        monitor = security_monitor.__class__(self.config_path)

        # Modify configuration
        monitor.thresholds['failed_logins_per_hour'] = 10
        monitor.log_security_event("test_config", "low")

        # Save configuration
        monitor.save_config()

        # Create new monitor and load configuration
        new_monitor = security_monitor.__class__(self.config_path)
        new_monitor.load_config()

        # Verify configuration was loaded
        self.assertEqual(new_monitor.thresholds['failed_logins_per_hour'], 10)
        self.assertEqual(len(new_monitor.security_events), 1)

if __name__ == '__main__':
    # Setup test environment
    logging.basicConfig(level=logging.INFO)

    # Run tests
    unittest.main(verbosity=2)