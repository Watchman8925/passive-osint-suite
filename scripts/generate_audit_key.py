#!/usr/bin/env python3
"""
Generate a new Ed25519 audit signing key pair.

This script generates a new cryptographic key pair for audit trail signing.
The private key should be stored securely and never committed to version control.

Usage:
    python scripts/generate_audit_key.py [--output-dir OUTPUT_DIR]

Options:
    --output-dir    Directory to save public key (optional, defaults to logs/audit)
    --help          Show this help message
"""

import argparse
import base64
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print("Error: cryptography library not installed")
    print("Install with: pip install cryptography")
    sys.exit(1)


def generate_key_pair(output_dir: str = None):
    """Generate a new Ed25519 key pair."""

    # Generate new Ed25519 key pair
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Export private key as PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Export private key as base64-encoded PEM for environment variable
    encoded_private = base64.b64encode(private_pem).decode()

    # Export public key as PEM
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Display results
    print("=" * 80)
    print("🔐 New Audit Signing Key Generated Successfully")
    print("=" * 80)
    print()

    print("⚠️  CRITICAL SECURITY NOTICE")
    print("-" * 80)
    print("The private key below must be kept SECRET and SECURE.")
    print("- DO NOT commit this key to version control")
    print("- DO NOT share this key via email or chat")
    print("- DO NOT store this key in unencrypted files")
    print("- DO store in a secret manager (AWS Secrets Manager, Azure Key Vault, etc.)")
    print("- DO add to .env file for development (ensure .env is in .gitignore)")
    print("-" * 80)
    print()

    print("📋 PRIVATE KEY (Base64-encoded PEM)")
    print("=" * 80)
    print("Add this to your .env file or secret manager:")
    print()
    print(f"AUDIT_SIGNING_KEY={encoded_private}")
    print()
    print("=" * 80)
    print()

    print("✅ PUBLIC KEY (Can be shared)")
    print("=" * 80)
    print(public_pem.decode())
    print("=" * 80)
    print()

    # Optionally save public key to file
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        public_key_file = output_path / "audit_public_key.pem"
        with open(public_key_file, "wb") as f:
            f.write(public_pem)

        print(f"✅ Public key saved to: {public_key_file}")
        print()

    print("📖 Next Steps:")
    print("-" * 80)
    print("1. Copy the AUDIT_SIGNING_KEY value above")
    print("2. For development:")
    print("   - Add to .env file (never commit this file)")
    print("   - Verify .env is in .gitignore")
    print("3. For production:")
    print("   - Store in secret manager (AWS Secrets Manager, Azure Key Vault, etc.)")
    print("   - Set as environment variable in deployment")
    print("4. Keep the public key for signature verification")
    print("5. Document this key generation event")
    print("-" * 80)
    print()

    print("🔄 Key Rotation Reminder:")
    print("-" * 80)
    print("- Rotate keys every 90 days (or per your security policy)")
    print("- Keep old public keys for verifying historical signatures")
    print("- Document all key rotation events")
    print("-" * 80)
    print()

    return encoded_private, public_pem.decode()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate a new Ed25519 audit signing key pair",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate key and display only
  python scripts/generate_audit_key.py

  # Generate key and save public key to custom directory
  python scripts/generate_audit_key.py --output-dir ./keys

Security Notes:
  - Never commit private keys to version control
  - Use environment variables or secret managers for storage
  - Rotate keys regularly (every 90 days recommended)
  - Keep old public keys for signature verification
        """,
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        help="Directory to save public key (default: logs/audit)",
    )

    args = parser.parse_args()

    # Generate the key pair
    output_dir = args.output_dir or "logs/audit"
    generate_key_pair(output_dir)


if __name__ == "__main__":
    main()
