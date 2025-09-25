"""
Immutable audit trail system with cryptographic signatures.
Provides tamper-evident logging for all OSINT operations.
"""

import base64
import hashlib
import json
import logging
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Represents a single audit log entry."""
    timestamp: str
    operation: str
    actor: str
    target: Optional[str]
    metadata: Dict[str, Any]
    session_id: str
    entry_id: str
    previous_hash: Optional[str] = None
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    def to_canonical_string(self) -> str:
        """Convert to canonical string for hashing/signing."""
        # Exclude signature from canonical representation
        data = {k: v for k, v in self.to_dict().items() if k != 'signature'}
        return json.dumps(data, sort_keys=True, separators=(',', ':'))


class AuditTrail:
    """
    Immutable audit trail with cryptographic signatures.
    
    Features:
    - ED25519 signatures for each entry
    - Hash chaining for tamper detection
    - Thread-safe operations
    - Configurable storage backends
    - Verification and integrity checking
    """
    
    def __init__(self, 
                 audit_dir: str = "logs/audit",
                 key_file: Optional[str] = None,
                 auto_rotate: bool = True,
                 max_entries_per_file: int = 10000):
        """
        Initialize audit trail.
        
        Args:
            audit_dir: Directory to store audit logs
            key_file: Path to signing key file (will generate if not exists)
            auto_rotate: Whether to automatically rotate log files
            max_entries_per_file: Maximum entries per log file
        """
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        
        self.auto_rotate = auto_rotate
        self.max_entries_per_file = max_entries_per_file
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Load or generate signing keys
        self.key_file = key_file or self.audit_dir / "audit_signing_key.pem"
        self._load_or_generate_keys()
        
        # Current log file and state
        self._current_log_file = None
        self._current_entries_count = 0
        self._last_hash = None
        
        # Initialize current log file
        self._initialize_current_log()
        
        logger.info(f"Audit trail initialized at {self.audit_dir}")
    
    def _load_or_generate_keys(self):
        """Load existing signing keys or generate new ones."""
        try:
            if Path(self.key_file).exists():
                # Load existing private key
                with open(self.key_file, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                logger.info("Loaded existing audit signing key")
            else:
                # Generate new ED25519 key pair
                self.private_key = ed25519.Ed25519PrivateKey.generate()
                
                # Save private key
                with open(self.key_file, 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption()
                    ))
                
                # Save public key for verification
                public_key_file = self.audit_dir / "audit_public_key.pem"
                with open(public_key_file, 'wb') as f:
                    f.write(self.private_key.public_key().public_bytes(
                        encoding=Encoding.PEM,
                        format=PublicFormat.SubjectPublicKeyInfo
                    ))
                
                logger.info("Generated new audit signing key pair")
            
            self.public_key = self.private_key.public_key()
            
        except Exception as e:
            logger.error(f"Failed to load/generate audit keys: {e}")
            raise
    
    def _initialize_current_log(self):
        """Initialize the current log file."""
        with self._lock:
            # Find the most recent log file
            log_files = sorted(self.audit_dir.glob("audit_*.jsonl"))
            
            if log_files and not self.auto_rotate:
                # Use the most recent file
                self._current_log_file = log_files[-1]
                
                # Count existing entries
                self._current_entries_count = sum(
                    1 for _ in open(self._current_log_file)
                )
                
                # Get last hash from last entry
                self._last_hash = self._get_last_hash_from_file(self._current_log_file)
            else:
                # Create new log file
                self._rotate_log_file()
    
    def _rotate_log_file(self):
        """Create a new log file for rotation."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._current_log_file = self.audit_dir / f"audit_{timestamp}.jsonl"
        self._current_entries_count = 0
        self._last_hash = None
        
        logger.info(f"Rotated to new audit log: {self._current_log_file}")
    
    def _get_last_hash_from_file(self, file_path: Path) -> Optional[str]:
        """Get the hash of the last entry in a file."""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1].strip())
                    return self._calculate_entry_hash(last_entry)
        except Exception as e:
            logger.warning(f"Could not get last hash from {file_path}: {e}")
        return None
    
    def _calculate_entry_hash(self, entry_dict: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of an entry."""
        # Create canonical representation for hashing
        canonical = json.dumps(entry_dict, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def _sign_entry(self, entry: AuditEntry) -> str:
        """Sign an audit entry with ED25519."""
        canonical_data = entry.to_canonical_string().encode()
        signature = self.private_key.sign(canonical_data)
        return base64.b64encode(signature).decode()
    
    def log_operation(self,
                     operation: str,
                     actor: str,
                     target: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None,
                     session_id: Optional[str] = None) -> str:
        """
        Log an operation to the audit trail.
        
        Args:
            operation: Type of operation (e.g., 'domain_lookup', 'file_analysis')
            actor: Who performed the operation (user, module, etc.)
            target: Target of the operation (domain, IP, file, etc.)
            metadata: Additional operation metadata
            session_id: Session identifier for grouping operations
        
        Returns:
            Entry ID of the logged operation
        """
        with self._lock:
            # Check if we need to rotate
            if (self.auto_rotate and 
                self._current_entries_count >= self.max_entries_per_file):
                self._rotate_log_file()
            
            # Create entry
            now = datetime.now(timezone.utc)
            entry_id = hashlib.sha256(
                f"{now.isoformat()}{operation}{actor}{target}".encode()
            ).hexdigest()[:16]
            
            entry = AuditEntry(
                timestamp=now.isoformat(),
                operation=operation,
                actor=actor,
                target=target,
                metadata=metadata or {},
                session_id=session_id or "default",
                entry_id=entry_id,
                previous_hash=self._last_hash
            )
            
            # Sign the entry
            entry.signature = self._sign_entry(entry)
            
            # Write to log file
            with open(self._current_log_file, 'a') as f:
                f.write(json.dumps(entry.to_dict()) + '\n')
            
            # Update state
            self._current_entries_count += 1
            self._last_hash = self._calculate_entry_hash(entry.to_dict())
            
            logger.debug(f"Logged audit entry: {entry_id}")
            return entry_id
    
    def verify_entry(self, entry_dict: Dict[str, Any]) -> bool:
        """
        Verify the cryptographic signature of an audit entry.
        
        Args:
            entry_dict: Dictionary representation of audit entry
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            signature = entry_dict.get('signature')
            if not signature:
                return False
            
            # Recreate entry without signature for verification
            entry_copy = {k: v for k, v in entry_dict.items() if k != 'signature'}
            canonical_data = json.dumps(
                entry_copy, sort_keys=True, separators=(',', ':')
            ).encode()
            
            # Verify signature
            signature_bytes = base64.b64decode(signature.encode())
            self.public_key.verify(signature_bytes, canonical_data)
            return True
            
        except Exception as e:
            logger.warning(f"Entry signature verification failed: {e}")
            return False
    
    def verify_chain_integrity(self, log_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Verify the integrity of the audit trail chain.
        
        Args:
            log_file: Specific log file to verify (None for current)
        
        Returns:
            Verification results
        """
        if log_file is None:
            log_file = self._current_log_file
        
        results = {
            'file': str(log_file),
            'total_entries': 0,
            'verified_entries': 0,
            'signature_failures': 0,
            'hash_chain_failures': 0,
            'integrity_verified': True,
            'errors': []
        }
        
        try:
            with open(log_file, 'r') as f:
                previous_hash = None
                
                for line_num, line in enumerate(f, 1):
                    try:
                        entry = json.loads(line.strip())
                        results['total_entries'] += 1
                        
                        # Verify signature
                        if self.verify_entry(entry):
                            results['verified_entries'] += 1
                        else:
                            results['signature_failures'] += 1
                            results['integrity_verified'] = False
                            results['errors'].append(
                                f"Line {line_num}: Signature verification failed"
                            )
                        
                        # Verify hash chain
                        if entry.get('previous_hash') != previous_hash:
                            results['hash_chain_failures'] += 1
                            results['integrity_verified'] = False
                            results['errors'].append(
                                f"Line {line_num}: Hash chain broken"
                            )
                        
                        # Calculate hash for next iteration
                        previous_hash = self._calculate_entry_hash(entry)
                        
                    except json.JSONDecodeError as e:
                        results['errors'].append(
                            f"Line {line_num}: JSON decode error: {e}"
                        )
                        results['integrity_verified'] = False
        
        except Exception as e:
            results['errors'].append(f"Failed to verify {log_file}: {e}")
            results['integrity_verified'] = False
        
        return results
    
    def search_entries(self,
                      operation: Optional[str] = None,
                      actor: Optional[str] = None,
                      target: Optional[str] = None,
                      session_id: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Search audit entries with filters.
        
        Args:
            operation: Filter by operation type
            actor: Filter by actor
            target: Filter by target
            session_id: Filter by session ID
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of results
        
        Returns:
            List of matching audit entries
        """
        results = []
        
        # Search all log files
        log_files = sorted(self.audit_dir.glob("audit_*.jsonl"))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            
                            # Apply filters
                            if operation and entry.get('operation') != operation:
                                continue
                            if actor and entry.get('actor') != actor:
                                continue
                            if target and entry.get('target') != target:
                                continue
                            if session_id and entry.get('session_id') != session_id:
                                continue
                            
                            # Time filters
                            entry_time = datetime.fromisoformat(entry['timestamp'])
                            if start_time and entry_time < start_time:
                                continue
                            if end_time and entry_time > end_time:
                                continue
                            
                            results.append(entry)
                            
                            # Limit check
                            if limit and len(results) >= limit:
                                return results
                                
                        except json.JSONDecodeError:
                            continue
                            
            except Exception as e:
                logger.warning(f"Failed to search {log_file}: {e}")
        
        return results
    
    def search_operations(self,
                         actor: Optional[str] = None,
                         operation: Optional[str] = None,
                         limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Search audit operations with simplified parameters.
        
        Args:
            actor: Filter by actor
            operation: Filter by operation type
            limit: Maximum number of results
        
        Returns:
            List of matching audit entries
        """
        return self.search_entries(
            operation=operation,
            actor=actor,
            limit=limit
        )
    
    def export_audit_trail(self, output_file: str, format: str = 'json') -> bool:
        """
        Export the complete audit trail.
        
        Args:
            output_file: Output file path
            format: Export format ('json', 'csv')
        
        Returns:
            True if export successful, False otherwise
        """
        try:
            entries = self.search_entries()  # Get all entries
            
            if format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(entries, f, indent=2)
            
            elif format == 'csv':
                import csv
                
                if entries:
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=entries[0].keys())
                        writer.writeheader()
                        writer.writerows(entries)
            
            logger.info(f"Exported {len(entries)} audit entries to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export audit trail: {e}")
            return False


# Global audit trail instance
audit_trail = AuditTrail()


# Decorator for automatic audit logging
def audit_operation(operation: str, actor: str = "system"):
    """
    Decorator to automatically audit function calls.
    
    Args:
        operation: Operation name
        actor: Actor performing the operation
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract target from arguments if possible
            target = None
            if args:
                if isinstance(args[0], str):
                    target = args[0]
            
            metadata = {
                'function': func.__name__,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            }
            
            # Log start of operation
            entry_id = audit_trail.log_operation(
                operation=f"{operation}_start",
                actor=actor,
                target=target,
                metadata=metadata
            )
            
            try:
                result = func(*args, **kwargs)
                
                # Log successful completion
                audit_trail.log_operation(
                    operation=f"{operation}_complete",
                    actor=actor,
                    target=target,
                    metadata={**metadata, 'status': 'success', 'start_entry': entry_id}
                )
                
                return result
                
            except Exception as e:
                # Log failure
                audit_trail.log_operation(
                    operation=f"{operation}_failed",
                    actor=actor,
                    target=target,
                    metadata={
                        **metadata, 'status': 'failed', 
                        'error': str(e), 'start_entry': entry_id
                    }
                )
                raise
        
        return wrapper
    return decorator


if __name__ == "__main__":
    # Example usage
    trail = AuditTrail()
    
    # Log some operations
    trail.log_operation("domain_lookup", "user", "example.com", {"resolver": "doh"})
    trail.log_operation(
        "file_analysis", "media_forensics", "image.jpg", {"type": "exif"}
    )
    
    # Verify integrity
    verification = trail.verify_chain_integrity()
    print(f"Integrity verified: {verification['integrity_verified']}")
    
    # Search entries
    entries = trail.search_entries(operation="domain_lookup")
    print(f"Found {len(entries)} domain lookup entries")