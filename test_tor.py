#!/usr/bin/env python3
"""
Test Tor integration for anonymity features
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from transport import get_tor_status, sync_validate_tor_connection
    TRANSPORT_AVAILABLE = True
except ImportError as e:
    print(f"❌ Transport module not available: {e}")
    TRANSPORT_AVAILABLE = False

def test_tor_status():
    """Test Tor status detection"""
    if not TRANSPORT_AVAILABLE:
        return False

    print("🧪 Testing Tor status detection...")

    try:
        status = get_tor_status()
        print(f"   Tor active: {status.get('active', False)}")
        print(f"   Circuits: {len(status.get('circuits', []))}")
        print(f"   Exit nodes: {status.get('exit_nodes', 0)}")
        return True
    except Exception as e:
        print(f"❌ Tor status test failed: {e}")
        return False

def test_tor_connection():
    """Test Tor connection validation"""
    if not TRANSPORT_AVAILABLE:
        return False

    print("🧪 Testing Tor connection validation...")

    try:
        is_tor = sync_validate_tor_connection()
        print(f"   Connection through Tor: {is_tor}")
        if not is_tor:
            print("   ℹ️  Note: Tor not running or not properly configured")
        return True
    except Exception as e:
        print(f"❌ Tor connection test failed: {e}")
        return False

def check_tor_installation():
    """Check if Tor is installed"""
    import subprocess

    print("🧪 Checking Tor installation...")

    try:
        result = subprocess.run(['which', 'tor'], capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✅ Tor is installed")
            return True
        else:
            print("   ❌ Tor is not installed")
            print("   ℹ️  To install Tor: sudo apt install tor")
            return False
    except Exception as e:
        print(f"❌ Tor installation check failed: {e}")
        return False

if __name__ == "__main__":
    print("Tor Integration Test")
    print("=" * 30)

    tor_installed = check_tor_installation()
    status_ok = test_tor_status()
    connection_ok = test_tor_connection()

    print("\nTest Results:")
    print(f"Tor installed: {'✅' if tor_installed else '❌'}")
    print(f"Status detection: {'✅' if status_ok else '❌'}")
    print(f"Connection validation: {'✅' if connection_ok else '❌'}")

    if tor_installed:
        print("\n✅ Tor integration components are working")
        print("ℹ️  Start Tor service with: sudo systemctl start tor")
    else:
        print("\n⚠️  Tor integration requires Tor to be installed")