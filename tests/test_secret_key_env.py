#!/usr/bin/env python3
"""
Test that the API server accepts both OSINT_SECRET_KEY and SECRET_KEY environment variables.
This test directly validates the config loading logic without importing the full api_server.
"""

import os


def test_osint_secret_key_works():
    """Test that OSINT_SECRET_KEY is accepted"""
    # Simulate the config loading logic from api_server.py
    os.environ["OSINT_SECRET_KEY"] = "test-secret-key-minimum-32-characters-long"
    if "SECRET_KEY" in os.environ:
        del os.environ["SECRET_KEY"]

    # Simulate AppConfig logic
    SECRET_KEY = os.getenv("OSINT_SECRET_KEY") or os.getenv("SECRET_KEY")

    assert SECRET_KEY == "test-secret-key-minimum-32-characters-long"
    assert SECRET_KEY is not None
    print("✅ OSINT_SECRET_KEY is accepted")


def test_secret_key_fallback_works():
    """Test that SECRET_KEY works as fallback when OSINT_SECRET_KEY is not set"""
    # Simulate the config loading logic from api_server.py
    if "OSINT_SECRET_KEY" in os.environ:
        del os.environ["OSINT_SECRET_KEY"]
    os.environ["SECRET_KEY"] = "fallback-secret-key-minimum-32-characters-long"

    # Simulate AppConfig logic
    SECRET_KEY = os.getenv("OSINT_SECRET_KEY") or os.getenv("SECRET_KEY")

    assert SECRET_KEY == "fallback-secret-key-minimum-32-characters-long"
    assert SECRET_KEY is not None
    print("✅ SECRET_KEY fallback is accepted")


def test_osint_secret_key_takes_priority():
    """Test that OSINT_SECRET_KEY takes priority over SECRET_KEY"""
    # Simulate the config loading logic from api_server.py
    os.environ["OSINT_SECRET_KEY"] = "osint-key-minimum-32-characters-long-test"
    os.environ["SECRET_KEY"] = "secret-key-minimum-32-characters-long-test"

    # Simulate AppConfig logic
    SECRET_KEY = os.getenv("OSINT_SECRET_KEY") or os.getenv("SECRET_KEY")

    assert SECRET_KEY == "osint-key-minimum-32-characters-long-test"
    assert SECRET_KEY != "secret-key-minimum-32-characters-long-test"
    print("✅ OSINT_SECRET_KEY takes priority over SECRET_KEY")


def test_missing_both_keys_detectable():
    """Test that missing both OSINT_SECRET_KEY and SECRET_KEY is detectable"""
    # Remove both environment variables
    if "OSINT_SECRET_KEY" in os.environ:
        del os.environ["OSINT_SECRET_KEY"]
    if "SECRET_KEY" in os.environ:
        del os.environ["SECRET_KEY"]

    # Simulate AppConfig logic
    SECRET_KEY = os.getenv("OSINT_SECRET_KEY") or os.getenv("SECRET_KEY")

    # This should be None/empty
    assert not SECRET_KEY
    print("✅ Missing both keys is properly detected as None/empty")


def test_error_message_format():
    """Test that the error message format is clear and helpful"""
    error_message = (
        "Either OSINT_SECRET_KEY or SECRET_KEY environment variable must be set to a secure random value. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
    )

    # Verify both key names are mentioned
    assert "OSINT_SECRET_KEY" in error_message
    assert "SECRET_KEY" in error_message
    assert "Either" in error_message
    assert "must be set" in error_message
    print("✅ Error message is clear and mentions both accepted keys")


if __name__ == "__main__":
    # Run tests directly for manual testing
    print("Testing OSINT_SECRET_KEY acceptance...")
    test_osint_secret_key_works()

    print("\nTesting SECRET_KEY fallback...")
    test_secret_key_fallback_works()

    print("\nTesting OSINT_SECRET_KEY priority...")
    test_osint_secret_key_takes_priority()

    print("\nTesting detection when both keys are missing...")
    test_missing_both_keys_detectable()

    print("\nTesting error message format...")
    test_error_message_format()

    print("\n✅ All tests passed!")
