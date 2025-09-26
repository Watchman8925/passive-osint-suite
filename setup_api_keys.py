#!/usr/bin/env python3
"""
Secure API Key Setup Script
============================

This script helps you securely configure API keys for the OSINT Suite.
API keys are encrypted and stored securely using Fernet encryption.
"""

import sys
import os
import getpass
import time

# Add security module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'security'))

from security.secrets_manager import secrets_manager

def setup_api_key(service_name, env_var, description):
    """Set up an API key for a specific service."""
    print(f"\n🔑 Setting up {service_name}")
    print(f"   {description}")
    print(f"   Environment variable: {env_var}")

    # Check if already configured
    existing_key = secrets_manager.get_secret(f"api_key_{service_name.lower()}")
    if existing_key:
        print(f"   ✅ Already configured (length: {len(existing_key)})")
        choice = input("   Update key? (y/N): ").lower().strip()
        if choice != 'y':
            return True

    # Get API key from user
    while True:
        api_key = getpass.getpass(f"   Enter {service_name} API key (hidden): ").strip()

        if not api_key:
            print("   ❌ No key provided, skipping")
            return False

        # Show the key briefly for confirmation
        print(f"   📋 You entered: {api_key}")
        print("   ⚠️  Key will be hidden in 3 seconds...")

        # Wait 3 seconds then clear the screen
        time.sleep(3)
        print("\033[2J\033[H", end="")  # Clear screen

        # Confirm the key
        print(f"   ✅ Confirm: Save this {service_name} API key? (y/N): ", end="")
        confirm = input().lower().strip()

        if confirm == 'y':
            break
        else:
            print("   🔄 Let's try again...")
            continue

    # Store securely
    success = secrets_manager.store_secret(f"api_key_{service_name.lower()}", api_key)

    if success:
        print(f"   ✅ {service_name} API key stored securely")
        return True
    else:
        print(f"   ❌ Failed to store {service_name} API key")
        return False

def main():
    """Main setup function."""
    print("🔒 OSINT Suite Secure API Key Setup")
    print("=" * 40)
    print("This script will help you configure API keys securely.")
    print("Keys are encrypted using Fernet encryption and stored locally.")
    print()

    # Show current status
    stats = secrets_manager.get_statistics()
    print("📊 Current Status:")
    print(f"   Encryption: {'✅ Enabled' if stats['encryption_enabled'] else '❌ Disabled'}")
    print(f"   Stored secrets: {stats['total_secrets']}")
    print()

    # API services to configure
    services = [
        ("OpenAI", "OPENAI_API_KEY", "Required for AI-powered analysis and LLM features"),
        ("Shodan", "SHODAN_API_KEY", "Network scanning and device intelligence"),
        ("Censys", "CENSYS_API_ID", "Certificate and network intelligence"),
        ("VirusTotal", "VIRUSTOTAL_API_KEY", "File and URL analysis"),
        ("Perplexity", "PERPLEXITY_API_KEY", "Advanced web search and research"),
        ("HunterIO", "HUNTER_API_KEY", "Email address discovery"),
        ("Clearbit", "CLEARBIT_API_KEY", "Company and person enrichment"),
        ("Spyse", "SPYSE_API_KEY", "DNS and network intelligence"),
        ("SecurityTrails", "SECURITYTRAILS_API_KEY", "DNS history and intelligence"),
        ("IPInfo", "IPINFO_TOKEN", "IP geolocation and intelligence"),
    ]

    configured = 0
    total = len(services)

    for service_name, env_var, description in services:
        try:
            if setup_api_key(service_name, env_var, description):
                configured += 1
        except KeyboardInterrupt:
            print("\n❌ Setup interrupted by user")
            break
        except Exception as e:
            print(f"❌ Error setting up {service_name}: {e}")

    print("\n🎉 Setup complete!")
    print(f"   Configured: {configured}/{total} services")
    print(f"   Total stored secrets: {secrets_manager.get_statistics()['total_secrets']}")

    if configured > 0:
        print("\n💡 Tips:")
        print("   • API keys are encrypted and stored securely")
        print("   • You can re-run this script to update keys")
        print("   • Use 'python3 -c \"from security.secrets_manager import secrets_manager; print(secrets_manager.list_secrets())\"' to list stored keys")
        print("   • The suite will automatically use these keys")

    print("\n🔍 To test your API keys, run:")
    print("   python3 security/api_key_manager.py --validate")

    # Ask if they want to run again
    print("\n🔄 Run setup again? (y/N): ", end="")
    try:
        again = input().lower().strip()
        if again == 'y':
            print("\n" + "="*50)
            main()  # Recursive call to restart
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)