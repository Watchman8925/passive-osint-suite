#!/usr/bin/env python3
"""
Unit tests for safety helpers in src/passive_osint_common/safety.py

Tests validate:
- safe_request enforces timeouts and handles errors
- handle_exceptions catches exceptions and returns structured errors
- input_validation validates function inputs
- configure_logger sets up proper logging
"""

import pytest
import logging
import sys
from pathlib import Path
from unittest.mock import patch, Mock
import requests

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.passive_osint_common.safety import (
    safe_request,
    handle_exceptions,
    input_validation,
    configure_logger,
    is_non_empty_string,
    is_valid_url,
    is_positive_integer,
    is_in_range,
    is_valid_email,
    is_valid_domain,
    is_valid_ip,
)


class TestSafeRequest:
    """Tests for safe_request function"""

    def test_safe_request_enforces_timeout(self):
        """Test that safe_request enforces timeout"""
        # Mock a timeout exception
        with patch("requests.Session.request") as mock_request:
            mock_request.side_effect = requests.exceptions.Timeout("Request timed out")

            result = safe_request("https://example.com", timeout=1)

            assert result is None, "Should return None on timeout"

    def test_safe_request_handles_connection_error(self):
        """Test that safe_request handles connection errors"""
        with patch("requests.Session.request") as mock_request:
            mock_request.side_effect = requests.exceptions.ConnectionError(
                "Connection failed"
            )

            result = safe_request("https://nonexistent.example.com")

            assert result is None, "Should return None on connection error"

    def test_safe_request_validates_url(self):
        """Test that safe_request validates URL format"""
        # Invalid URL (no scheme)
        result = safe_request("not-a-valid-url")
        assert result is None, "Should return None for invalid URL"

        # Invalid URL (no netloc)
        result = safe_request("http://")
        assert result is None, "Should return None for URL without netloc"

    def test_safe_request_successful(self):
        """Test that safe_request returns response on success"""
        with patch("requests.Session.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.ok = True
            mock_response.headers = {}
            mock_request.return_value = mock_response

            result = safe_request("https://example.com", timeout=10)

            assert result is not None, "Should return response on success"
            assert result.status_code == 200

    def test_safe_request_rate_limit_warning(self):
        """Test that safe_request logs warning when rate limit is low"""
        with patch("requests.Session.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {"X-RateLimit-Remaining": "5"}
            mock_request.return_value = mock_response

            with patch("src.passive_osint_common.safety.logger") as mock_logger:
                safe_request("https://example.com")

                # Check that warning was logged
                mock_logger.warning.assert_called()

    def test_safe_request_with_rate_limit_delay(self):
        """Test that safe_request respects rate limit delay"""
        with patch("time.sleep") as mock_sleep:
            with patch("requests.Session.request") as mock_request:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.headers = {}
                mock_request.return_value = mock_response

                safe_request("https://example.com", rate_limit_delay=2.0)

                mock_sleep.assert_called_once_with(2.0)


class TestHandleExceptions:
    """Tests for handle_exceptions decorator"""

    def test_handle_exceptions_catches_exception(self):
        """Test that handle_exceptions catches exceptions"""

        @handle_exceptions(default_return={"status": "error"})
        def failing_function():
            raise ValueError("Test error")

        result = failing_function()

        assert result is not None, "Should return default value"
        assert "status" in result
        assert result["status"] == "error"
        assert "error" in result
        assert "error_type" in result

    def test_handle_exceptions_returns_normal_on_success(self):
        """Test that handle_exceptions doesn't affect normal execution"""

        @handle_exceptions(default_return={"status": "error"})
        def successful_function():
            return {"status": "success", "data": "result"}

        result = successful_function()

        assert result["status"] == "success"
        assert result["data"] == "result"

    def test_handle_exceptions_with_simple_default(self):
        """Test handle_exceptions with non-dict default return"""

        @handle_exceptions(default_return=None)
        def failing_function():
            raise RuntimeError("Test error")

        result = failing_function()

        assert result is None, "Should return None on error"

    def test_handle_exceptions_can_reraise(self):
        """Test that handle_exceptions can re-raise exceptions"""

        @handle_exceptions(default_return=None, reraise=True)
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_function()


class TestInputValidation:
    """Tests for input_validation decorator"""

    def test_input_validation_accepts_valid_input(self):
        """Test that input_validation accepts valid input"""

        @input_validation(name=is_non_empty_string, count=is_positive_integer)
        def test_function(name: str, count: int):
            return f"{name}: {count}"

        result = test_function("test", 5)
        assert result == "test: 5"

    def test_input_validation_rejects_invalid_input(self):
        """Test that input_validation rejects invalid input"""

        @input_validation(name=is_non_empty_string, count=is_positive_integer)
        def test_function(name: str, count: int):
            return f"{name}: {count}"

        # Invalid name (empty string)
        with pytest.raises(ValueError):
            test_function("", 5)

        # Invalid count (negative)
        with pytest.raises(ValueError):
            test_function("test", -1)

    def test_input_validation_with_custom_validator(self):
        """Test input_validation with custom validator"""

        @input_validation(value=lambda x: x > 0 and x < 100)
        def test_function(value: int):
            return value * 2

        # Valid
        result = test_function(50)
        assert result == 100

        # Invalid (too high)
        with pytest.raises(ValueError):
            test_function(150)


class TestValidationHelpers:
    """Tests for validation helper functions"""

    def test_is_non_empty_string(self):
        """Test is_non_empty_string validator"""
        assert is_non_empty_string("hello")
        assert not is_non_empty_string("")
        assert not is_non_empty_string("   ")
        assert not is_non_empty_string(123)
        assert not is_non_empty_string(None)

    def test_is_valid_url(self):
        """Test is_valid_url validator"""
        assert is_valid_url("https://example.com")
        assert is_valid_url("http://example.com/path")
        assert is_valid_url("ftp://files.example.com")
        assert not is_valid_url("not-a-url")
        assert not is_valid_url("http://")
        assert not is_valid_url(123)

    def test_is_positive_integer(self):
        """Test is_positive_integer validator"""
        assert is_positive_integer(1)
        assert is_positive_integer(100)
        assert not is_positive_integer(0)
        assert not is_positive_integer(-1)
        assert not is_positive_integer(1.5)
        assert not is_positive_integer("1")

    def test_is_in_range(self):
        """Test is_in_range validator"""
        validator = is_in_range(1, 10)
        assert validator(5)
        assert validator(1)
        assert validator(10)
        assert not validator(0)
        assert not validator(11)

    def test_is_valid_email(self):
        """Test is_valid_email validator"""
        assert is_valid_email("user@example.com")
        assert is_valid_email("test.user+tag@example.co.uk")
        assert not is_valid_email("invalid@")
        assert not is_valid_email("@example.com")
        assert not is_valid_email("not-an-email")
        assert not is_valid_email(123)

    def test_is_valid_domain(self):
        """Test is_valid_domain validator"""
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.com")
        assert is_valid_domain("sub.sub.example.co.uk")
        assert not is_valid_domain("invalid")
        assert not is_valid_domain("example..com")
        assert not is_valid_domain("-example.com")
        assert not is_valid_domain(123)

    def test_is_valid_ip(self):
        """Test is_valid_ip validator"""
        # IPv4
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("8.8.8.8")

        # IPv6
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert is_valid_ip("::1")

        # Invalid
        assert not is_valid_ip("256.1.1.1")
        assert not is_valid_ip("not-an-ip")
        assert not is_valid_ip(123)


class TestConfigureLogger:
    """Tests for configure_logger function"""

    def test_configure_logger_creates_logger(self):
        """Test that configure_logger creates a logger"""
        logger = configure_logger("test_logger")

        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger"

    def test_configure_logger_sets_level(self):
        """Test that configure_logger sets the correct log level"""
        logger = configure_logger("test_logger_level", logging.DEBUG)

        assert logger.level == logging.DEBUG

    def test_configure_logger_adds_handler(self):
        """Test that configure_logger adds a handler"""
        logger = configure_logger("test_logger_handler")

        assert len(logger.handlers) > 0

    def test_configure_logger_idempotent(self):
        """Test that calling configure_logger multiple times doesn't add duplicate handlers"""
        logger1 = configure_logger("test_logger_idem")
        handler_count1 = len(logger1.handlers)

        logger2 = configure_logger("test_logger_idem")
        handler_count2 = len(logger2.handlers)

        assert handler_count1 == handler_count2, "Should not add duplicate handlers"


class TestIntegration:
    """Integration tests combining multiple safety features"""

    def test_combined_decorators(self):
        """Test using multiple decorators together"""

        @handle_exceptions(default_return={"status": "error"})
        @input_validation(url=is_valid_url, timeout=is_positive_integer)
        def fetch_data(url: str, timeout: int = 30):
            # Simulate a successful fetch
            return {"status": "success", "url": url}

        # Valid input
        result = fetch_data("https://example.com", 10)
        assert result["status"] == "success"

        # Invalid input - handle_exceptions will catch the ValueError
        result = fetch_data("not-a-url", 10)
        assert result["status"] == "error"
        assert "error" in result

    def test_safe_request_with_validation(self):
        """Test safe_request combined with input validation"""

        @input_validation(url=is_valid_url)
        def validated_request(url: str):
            return safe_request(url, timeout=5)

        # Invalid URL should fail validation before request
        with pytest.raises(ValueError):
            validated_request("invalid-url")


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
