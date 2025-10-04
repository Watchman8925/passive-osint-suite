"""
Secrets Manager Stub
===================

Basic secrets management functionality for API key storage and retrieval.
This is a stub implementation to satisfy import requirements.
"""

import os
import json
import base64
import secrets
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet


class SecretsManager:
    """
    Secure secrets manager for API keys and sensitive configuration.
    Uses Fernet encryption for secure storage.
    """

    def __init__(
        self, key_file: Optional[str] = None, secrets_file: Optional[str] = None
    ):
        self.key_file = key_file or os.path.join(
            os.path.dirname(__file__), "encryption.key"
        )
        self.secrets_file = secrets_file or os.path.join(
            os.path.dirname(__file__), "secrets.enc"
        )
        self._secrets = {}
        self._cipher = None
        self._initialize_encryption()
        self._load_secrets()

    def _initialize_encryption(self):
        """Initialize encryption with master key"""
        try:
            # Load or generate master key
            if os.path.exists(self.key_file):
                with open(self.key_file, "rb") as f:
                    key_data = f.read()
                    if len(key_data) == 32:
                        # Raw 32-byte key
                        master_key = key_data
                    elif len(key_data) == 64:
                        # Assume hex-encoded 32-byte key
                        master_key = bytes.fromhex(key_data.decode())
                    else:
                        # Assume base64 encoded
                        try:
                            master_key = base64.b64decode(key_data)
                        except Exception:
                            master_key = base64.b64decode(key_data.decode())
            else:
                # Generate new master key
                master_key = secrets.token_bytes(32)
                os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
                with open(self.key_file, "wb") as f:
                    f.write(base64.b64encode(master_key))
                # Set restrictive permissions
                os.chmod(self.key_file, 0o600)

            # Ensure key is 32 bytes
            if len(master_key) != 32:
                # Derive 32-byte key from existing key
                import hashlib

                master_key = hashlib.sha256(master_key).digest()

            # Create Fernet cipher
            self._cipher = Fernet(base64.b64encode(master_key))

        except Exception as e:
            print(f"Warning: Failed to initialize encryption: {e}")
            # Fallback to no encryption (not recommended)
            self._cipher = None

    def _load_secrets(self):
        """Load encrypted secrets from storage"""
        try:
            if os.path.exists(self.secrets_file):
                with open(self.secrets_file, "rb") as f:
                    encrypted_data = f.read()

                if self._cipher and encrypted_data:
                    decrypted_data = self._cipher.decrypt(encrypted_data)
                    self._secrets = json.loads(decrypted_data.decode())
                else:
                    # Fallback for unencrypted data
                    self._secrets = json.loads(encrypted_data.decode())
        except Exception as e:
            print(f"Warning: Could not load secrets file: {e}")
            self._secrets = {}

    def _save_secrets(self):
        """Save secrets to encrypted storage"""
        try:
            os.makedirs(os.path.dirname(self.secrets_file), exist_ok=True)

            json_data = json.dumps(self._secrets, indent=2)

            if self._cipher:
                encrypted_data = self._cipher.encrypt(json_data.encode())
                with open(self.secrets_file, "wb") as f:
                    f.write(encrypted_data)
                # Set restrictive permissions
                os.chmod(self.secrets_file, 0o600)
            else:
                # Never store secrets in clear text - encryption is mandatory
                raise RuntimeError("Encryption is not initialized. Cannot store secrets in clear text.")

        except Exception as e:
            print(f"Warning: Could not save secrets file: {e}")

    def get_secret(self, key: str, default: Any = None) -> Any:
        """Get a secret value by key."""
        return self._secrets.get(key, default)

    def set_secret(self, key: str, value: Any):
        """Set a secret value."""
        self._secrets[key] = value
        self._save_secrets()

    def store_secret(self, key: str, value: Any, **kwargs) -> bool:
        """Store a secret value (alias for set_secret with return value)."""
        try:
            self.set_secret(key, value)
            return True
        except Exception:
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get secrets manager statistics."""
        return {
            "total_secrets": len(self._secrets),
            "secrets_file": self.secrets_file,
            "key_file": self.key_file,
            "encryption_enabled": self._cipher is not None,
            "file_exists": os.path.exists(self.secrets_file),
            "key_exists": os.path.exists(self.key_file),
        }

    def has_secret(self, key: str) -> bool:
        """Check if a secret exists."""
        return key in self._secrets

    def list_secrets(self) -> Dict[str, Any]:
        """List all available secrets (without values for security)."""
        return {key: "***" for key in self._secrets.keys()}

    def delete_secret(self, key: str) -> bool:
        """Delete a secret."""
        if key in self._secrets:
            del self._secrets[key]
            self._save_secrets()
            return True
        return False

    def rotate_key(self) -> bool:
        """Rotate the encryption key (re-encrypts all secrets with new key)."""
        try:
            if not self._cipher:
                return False

            # Generate new key
            new_master_key = secrets.token_bytes(32)

            # Create new cipher
            new_cipher = Fernet(base64.b64encode(new_master_key))

            # Re-encrypt all secrets
            json_data = json.dumps(self._secrets, indent=2)
            new_encrypted_data = new_cipher.encrypt(json_data.encode())

            # Save new key
            with open(self.key_file, "wb") as f:
                f.write(base64.b64encode(new_master_key))

            # Save re-encrypted data
            with open(self.secrets_file, "wb") as f:
                f.write(new_encrypted_data)

            # Update cipher
            self._cipher = new_cipher

            # Set permissions
            os.chmod(self.key_file, 0o600)
            os.chmod(self.secrets_file, 0o600)

            return True

        except Exception as e:
            print(f"Warning: Key rotation failed: {e}")
            return False

    def get_all_secrets(self) -> Dict[str, Any]:
        """Get all secrets as a dictionary."""
        return self._secrets.copy()


# Global instance for backward compatibility
secrets_manager = SecretsManager()


def get_api_key(service: str) -> Optional[str]:
    """Backward compatibility function for getting API keys."""
    return secrets_manager.get_secret(f"api_key_{service}")


def store_api_key(service: str, api_key: str, **kwargs) -> bool:
    """Backward compatibility function for storing API keys."""
    try:
        secrets_manager.set_secret(f"api_key_{service}", api_key)
        return True
    except Exception:
        return False
