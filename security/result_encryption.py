"""
Result Encryption System for OSINT Suite
Provides secure encryption and storage of intelligence results
"""

import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class EncryptedResult:
    """Represents an encrypted intelligence result"""
    result_id: str
    encrypted_data: str
    salt: str
    operation: str
    target: str
    description: str
    created_at: float
    expires_at: Optional[float] = None
    burn_after_read: bool = False
    accessed: bool = False


class ResultEncryption:
    """
    Secure encryption and storage system for OSINT results
    """

    def __init__(self, storage_path: str = "output/encrypted_results"):
        self.storage_path = storage_path
        self.master_key = self._get_master_key()
        self.results: Dict[str, EncryptedResult] = {}
        self._load_results()

        # Ensure storage directory exists
        os.makedirs(storage_path, exist_ok=True)

    def _get_master_key(self) -> str:
        """Get or generate master encryption key"""
        key_file = "security/encryption.key"

        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                return f.read().strip()

        # Generate new master key
        master_key = secrets.token_hex(32)
        os.makedirs("security", exist_ok=True)

        with open(key_file, 'w') as f:
            f.write(master_key)

        # Set restrictive permissions
        os.chmod(key_file, 0o600)
        return master_key

    def _load_results(self) -> None:
        """Load encrypted results from storage"""
        index_file = os.path.join(self.storage_path, "index.json")

        if not os.path.exists(index_file):
            return

        try:
            with open(index_file, 'r') as f:
                data = json.load(f)

            for result_id, result_data in data.items():
                self.results[result_id] = EncryptedResult(
                    result_id=result_id,
                    encrypted_data=result_data['encrypted_data'],
                    salt=result_data['salt'],
                    operation=result_data['operation'],
                    target=result_data['target'],
                    description=result_data['description'],
                    created_at=result_data['created_at'],
                    expires_at=result_data.get('expires_at'),
                    burn_after_read=result_data.get('burn_after_read', False),
                    accessed=result_data.get('accessed', False)
                )

        except Exception as e:
            logger.error(f"Failed to load encrypted results: {e}")

    def _save_results(self) -> None:
        """Save encrypted results to storage"""
        index_file = os.path.join(self.storage_path, "index.json")

        try:
            data = {}
            for result_id, result in self.results.items():
                data[result_id] = {
                    'encrypted_data': result.encrypted_data,
                    'salt': result.salt,
                    'operation': result.operation,
                    'target': result.target,
                    'description': result.description,
                    'created_at': result.created_at,
                    'expires_at': result.expires_at,
                    'burn_after_read': result.burn_after_read,
                    'accessed': result.accessed
                }

            with open(index_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save encrypted results: {e}")

    def _generate_key(self, password: Optional[str] = None, salt: Optional[str] = None) -> str:
        """Generate encryption key from password and salt"""
        if password:
            salt = salt or secrets.token_hex(16)
            key_material = f"{password}{salt}{self.master_key}"
        else:
            salt = salt or secrets.token_hex(16)
            key_material = f"{self.master_key}{salt}"

        return hashlib.sha256(key_material.encode()).hexdigest()

    def _simple_encrypt(self, data: str, key: str) -> str:
        """Simple XOR encryption (replace with proper encryption in production)"""
        encrypted = []
        key_bytes = key.encode()

        for i, char in enumerate(data):
            key_char = key_bytes[i % len(key_bytes)]
            encrypted.append(chr(ord(char) ^ key_char))

        return ''.join(encrypted)

    def _simple_decrypt(self, data: str, key: str) -> str:
        """Simple XOR decryption"""
        return self._simple_encrypt(data, key)

    def encrypt_result(
        self,
        result_data: Dict[str, Any],
        operation: Optional[str] = None,
        target: Optional[str] = None,
        description: Optional[str] = None,
        expires_hours: Optional[int] = None,
        expires_in_hours: Optional[int] = None,
        password: Optional[str] = None,
        burn_after_read: bool = False
    ) -> Optional[str]:
        """Encrypt and store an intelligence result"""
        try:
            # Generate unique result ID
            result_id = secrets.token_hex(16)

            # Set expiration
            expires_at = None
            if expires_hours or expires_in_hours:
                hours = expires_hours or expires_in_hours
                expires_at = time.time() + (hours * 3600)

            # Prepare data for encryption
            data_to_encrypt = {
                'result_data': result_data,
                'metadata': {
                    'operation': operation or 'unknown',
                    'target': target or 'unknown',
                    'description': description or '',
                    'created_at': time.time(),
                    'expires_at': expires_at,
                    'burn_after_read': burn_after_read
                }
            }

            # Generate salt and key
            salt = secrets.token_hex(16)
            key = self._generate_key(password, salt)

            # Encrypt data
            json_data = json.dumps(data_to_encrypt)
            encrypted_data = self._simple_encrypt(json_data, key)

            # Create result object
            result = EncryptedResult(
                result_id=result_id,
                encrypted_data=encrypted_data,
                salt=salt,
                operation=operation or 'unknown',
                target=target or 'unknown',
                description=description or '',
                created_at=time.time(),
                expires_at=expires_at,
                burn_after_read=burn_after_read
            )

            # Store result
            self.results[result_id] = result
            self._save_results()

            # Save encrypted data to file
            result_file = os.path.join(self.storage_path, f"{result_id}.enc")
            with open(result_file, 'w') as f:
                json.dump({
                    'encrypted_data': encrypted_data,
                    'salt': salt
                }, f)

            logger.info(f"Result encrypted and stored: {result_id}")
            return result_id

        except Exception as e:
            logger.error(f"Failed to encrypt result: {e}")
            return None

    def decrypt_result(self, result_id: str, password: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Decrypt and retrieve an intelligence result"""
        try:
            if result_id not in self.results:
                logger.error(f"Result not found: {result_id}")
                return None

            result = self.results[result_id]

            # Check expiration
            if result.expires_at and time.time() > result.expires_at:
                logger.warning(f"Result expired: {result_id}")
                self.delete_result(result_id)
                return None

            # Check burn after read
            if result.burn_after_read and result.accessed:
                logger.warning(f"Result already accessed (burn after read): {result_id}")
                self.delete_result(result_id)
                return None

            # Load encrypted data from file
            result_file = os.path.join(self.storage_path, f"{result_id}.enc")
            if not os.path.exists(result_file):
                logger.error(f"Encrypted file not found: {result_file}")
                return None

            with open(result_file, 'r') as f:
                file_data = json.load(f)

            # Generate decryption key
            key = self._generate_key(password, file_data['salt'])

            # Decrypt data
            decrypted_json = self._simple_decrypt(file_data['encrypted_data'], key)
            data = json.loads(decrypted_json)

            # Mark as accessed
            result.accessed = True
            self._save_results()

            logger.info(f"Result decrypted: {result_id}")
            return data['result_data']

        except Exception as e:
            logger.error(f"Failed to decrypt result {result_id}: {e}")
            return None

    def delete_result(self, result_id: str) -> bool:
        """Delete an encrypted result"""
        try:
            if result_id not in self.results:
                return False

            # Remove from memory
            del self.results[result_id]

            # Remove files
            result_file = os.path.join(self.storage_path, f"{result_id}.enc")
            if os.path.exists(result_file):
                os.remove(result_file)

            # Save updated index
            self._save_results()

            logger.info(f"Result deleted: {result_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete result {result_id}: {e}")
            return False

    def list_encrypted_results(self) -> List[Dict[str, Any]]:
        """List all encrypted results"""
        results = []
        current_time = time.time()

        for result in self.results.values():
            # Skip expired results
            if result.expires_at and current_time > result.expires_at:
                continue

            results.append({
                'result_id': result.result_id,
                'operation': result.operation,
                'target': result.target,
                'description': result.description,
                'created_at': result.created_at,
                'expires_at': result.expires_at,
                'burn_after_read': result.burn_after_read,
                'accessed': result.accessed
            })

        return results

    def cleanup_expired(self) -> int:
        """Clean up expired results"""
        current_time = time.time()
        expired_ids = []

        for result_id, result in self.results.items():
            if result.expires_at and current_time > result.expires_at:
                expired_ids.append(result_id)

        for result_id in expired_ids:
            self.delete_result(result_id)

        logger.info(f"Cleaned up {len(expired_ids)} expired results")
        return len(expired_ids)


# Global instance
result_encryption = ResultEncryption()