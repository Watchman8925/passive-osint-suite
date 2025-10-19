# HashiCorp Vault Integration Guide

## Overview

This guide describes how to integrate HashiCorp Vault with the Passive OSINT Suite for secure credential storage, rotation, and audit logging. Vault provides a centralized, secure solution for managing secrets, API keys, and credentials.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication Methods](#authentication-methods)
- [Usage Examples](#usage-examples)
- [Rotation Policies](#rotation-policies)
- [Audit Logging](#audit-logging)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Passive OSINT Suite                      │
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                   │
│  │   Modules    │      │     API      │                   │
│  │  (38+ OSINT) │◄────►│   Services   │                   │
│  └──────┬───────┘      └──────┬───────┘                   │
│         │                     │                            │
│         └──────────┬──────────┘                            │
│                    │                                       │
│         ┌──────────▼──────────┐                           │
│         │  Vault Client (hvac) │                           │
│         └──────────┬──────────┘                           │
└────────────────────┼─────────────────────────────────────┘
                     │ TLS
                     │ (Token/AppRole)
           ┌─────────▼──────────┐
           │  HashiCorp Vault   │
           │                    │
           │  ┌──────────────┐  │
           │  │ Secret Store │  │
           │  │  - API Keys  │  │
           │  │  - Tokens    │  │
           │  │  - Passwords │  │
           │  └──────────────┘  │
           │                    │
           │  ┌──────────────┐  │
           │  │ Audit Log    │  │
           │  └──────────────┘  │
           └────────────────────┘
```

### Key Components

1. **Vault Server**: Centralized secret management system
2. **hvac Client**: Python library for Vault API interaction
3. **Authentication Backend**: Token-based or AppRole authentication
4. **Audit Backend**: Logs all access to secrets
5. **Secret Engines**: kv (key-value) for static secrets, database for dynamic credentials

---

## Prerequisites

### System Requirements

- HashiCorp Vault server (local or remote)
- Python 3.10+
- Network connectivity to Vault server
- TLS certificates (for production)

### Python Dependencies

```bash
pip install hvac requests
```

---

## Installation

### Option 1: Local Development (Docker)

```bash
# Start Vault in dev mode (WARNING: Not for production!)
docker run -d --name vault-dev \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root-token \
  vault:latest

# Export Vault address and token
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-root-token'

# Verify connection
vault status
```

### Option 2: Production Setup

```bash
# Install Vault
# macOS
brew install vault

# Linux
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Initialize Vault (first time only)
vault operator init

# Unseal Vault (requires 3 of 5 keys by default)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Login with root token
vault login <root-token>
```

---

## Configuration

### Environment Variables

Create a `.env` file (never commit this!):

```bash
# Vault Configuration
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=s.abcdefghijklmnop
VAULT_NAMESPACE=passive-osint  # Optional: for Vault Enterprise

# Alternative: Use AppRole
VAULT_ROLE_ID=role-id-here
VAULT_SECRET_ID=secret-id-here

# TLS Configuration (production)
VAULT_CACERT=/path/to/ca.crt
VAULT_CLIENT_CERT=/path/to/client.crt
VAULT_CLIENT_KEY=/path/to/client.key
```

### Application Configuration

Add to `config/vault_config.py`:

```python
import os
from typing import Optional

class VaultConfig:
    """Vault configuration settings"""
    
    # Connection settings
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    VAULT_NAMESPACE: Optional[str] = os.getenv("VAULT_NAMESPACE")
    
    # Authentication
    VAULT_TOKEN: Optional[str] = os.getenv("VAULT_TOKEN")
    VAULT_ROLE_ID: Optional[str] = os.getenv("VAULT_ROLE_ID")
    VAULT_SECRET_ID: Optional[str] = os.getenv("VAULT_SECRET_ID")
    
    # TLS settings
    VAULT_CACERT: Optional[str] = os.getenv("VAULT_CACERT")
    VAULT_CLIENT_CERT: Optional[str] = os.getenv("VAULT_CLIENT_CERT")
    VAULT_CLIENT_KEY: Optional[str] = os.getenv("VAULT_CLIENT_KEY")
    VAULT_SKIP_VERIFY: bool = os.getenv("VAULT_SKIP_VERIFY", "false").lower() == "true"
    
    # Secret paths
    SECRET_PATH_PREFIX: str = "secret/data/passive-osint"
    
    # Retry settings
    MAX_RETRIES: int = 3
    RETRY_BACKOFF: float = 1.0
```

---

## Authentication Methods

### 1. Token Authentication (Simple)

**Use for**: Development, admin access, CI/CD

```python
import hvac
import os

def get_vault_client_token():
    """Create Vault client with token authentication"""
    client = hvac.Client(
        url=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"),
        token=os.getenv("VAULT_TOKEN")
    )
    
    if not client.is_authenticated():
        raise Exception("Vault authentication failed")
    
    return client

# Usage
client = get_vault_client_token()
```

### 2. AppRole Authentication (Recommended for Production)

**Use for**: Application authentication, automated systems

```python
import hvac
import os

def get_vault_client_approle():
    """Create Vault client with AppRole authentication"""
    client = hvac.Client(
        url=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    )
    
    # Authenticate with AppRole
    role_id = os.getenv("VAULT_ROLE_ID")
    secret_id = os.getenv("VAULT_SECRET_ID")
    
    auth_response = client.auth.approle.login(
        role_id=role_id,
        secret_id=secret_id
    )
    
    # Set the token from AppRole login
    client.token = auth_response["auth"]["client_token"]
    
    if not client.is_authenticated():
        raise Exception("AppRole authentication failed")
    
    return client

# Usage
client = get_vault_client_approle()
```

### 3. Kubernetes Authentication

**Use for**: Applications running in Kubernetes

```python
import hvac
import os

def get_vault_client_k8s():
    """Create Vault client with Kubernetes authentication"""
    client = hvac.Client(
        url=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    )
    
    # Read Kubernetes service account token
    with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
        jwt = f.read()
    
    # Authenticate
    auth_response = client.auth.kubernetes.login(
        role="passive-osint-role",
        jwt=jwt
    )
    
    client.token = auth_response["auth"]["client_token"]
    
    return client
```

---

## Usage Examples

### Example 1: Basic Secret Storage and Retrieval

```python
#!/usr/bin/env python3
"""
Basic Vault integration example
Demonstrates storing and retrieving secrets
"""

import hvac
import os
import sys
from typing import Dict, Any, Optional

class VaultClient:
    """Simple Vault client wrapper"""
    
    def __init__(self):
        """Initialize Vault client"""
        self.vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.vault_token = os.getenv("VAULT_TOKEN")
        self.client = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Vault using token or AppRole"""
        self.client = hvac.Client(url=self.vault_addr)
        
        # Try token authentication first
        if self.vault_token:
            self.client.token = self.vault_token
            if self.client.is_authenticated():
                return
        
        # Try AppRole authentication
        role_id = os.getenv("VAULT_ROLE_ID")
        secret_id = os.getenv("VAULT_SECRET_ID")
        
        if role_id and secret_id:
            auth_response = self.client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
            )
            self.client.token = auth_response["auth"]["client_token"]
            if self.client.is_authenticated():
                return
        
        raise Exception("Vault authentication failed. Set VAULT_TOKEN or VAULT_ROLE_ID/VAULT_SECRET_ID")
    
    def write_secret(self, path: str, secret_data: Dict[str, Any]) -> bool:
        """
        Write secret to Vault
        
        Args:
            path: Secret path (e.g., "passive-osint/api-keys/shodan")
            secret_data: Dictionary of secret key-value pairs
        
        Returns:
            True if successful
        """
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data,
            )
            return True
        except Exception as e:
            print(f"Error writing secret: {e}")
            return False
    
    def read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Read secret from Vault
        
        Args:
            path: Secret path (e.g., "passive-osint/api-keys/shodan")
        
        Returns:
            Dictionary of secret data or None if not found
        """
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path
            )
            return response["data"]["data"]
        except Exception as e:
            print(f"Error reading secret: {e}")
            return None
    
    def list_secrets(self, path: str) -> Optional[list]:
        """
        List secrets at path
        
        Args:
            path: Secret path to list
        
        Returns:
            List of secret names or None if error
        """
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=path
            )
            return response["data"]["keys"]
        except Exception as e:
            print(f"Error listing secrets: {e}")
            return None
    
    def delete_secret(self, path: str) -> bool:
        """
        Delete secret (soft delete - can be recovered)
        
        Args:
            path: Secret path to delete
        
        Returns:
            True if successful
        """
        try:
            self.client.secrets.kv.v2.delete_latest_version_of_secret(
                path=path
            )
            return True
        except Exception as e:
            print(f"Error deleting secret: {e}")
            return False


# Example usage
if __name__ == "__main__":
    # Initialize client
    vault = VaultClient()
    
    # Store API keys
    print("Storing API keys...")
    vault.write_secret("passive-osint/api-keys/shodan", {
        "api_key": "your-shodan-api-key-here",
        "description": "Shodan API key for IP intelligence"
    })
    
    vault.write_secret("passive-osint/api-keys/virustotal", {
        "api_key": "your-virustotal-api-key-here",
        "description": "VirusTotal API key for malware analysis"
    })
    
    # Retrieve secrets
    print("\nRetrieving Shodan API key...")
    shodan_secret = vault.read_secret("passive-osint/api-keys/shodan")
    if shodan_secret:
        print(f"Shodan API Key: {shodan_secret['api_key'][:10]}...")
        print(f"Description: {shodan_secret['description']}")
    
    # List all API keys
    print("\nListing all API keys...")
    keys = vault.list_secrets("passive-osint/api-keys")
    if keys:
        for key in keys:
            print(f"  - {key}")
```

### Example 2: Integration with OSINT Modules

```python
#!/usr/bin/env python3
"""
Vault integration for OSINT modules
Demonstrates how to retrieve credentials for various OSINT services
"""

import hvac
import os
from typing import Optional, Dict, Any
from functools import lru_cache

class OSINTVaultManager:
    """Manages Vault secrets for OSINT modules"""
    
    def __init__(self):
        """Initialize Vault manager"""
        self.client = hvac.Client(
            url=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"),
            token=os.getenv("VAULT_TOKEN")
        )
        
        if not self.client.is_authenticated():
            raise Exception("Vault authentication failed")
        
        self.secret_prefix = "passive-osint"
    
    @lru_cache(maxsize=100)
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a service (cached)
        
        Args:
            service: Service name (e.g., "shodan", "virustotal")
        
        Returns:
            API key string or None
        """
        try:
            path = f"{self.secret_prefix}/api-keys/{service}"
            response = self.client.secrets.kv.v2.read_secret_version(path=path)
            return response["data"]["data"].get("api_key")
        except Exception as e:
            print(f"Error retrieving {service} API key: {e}")
            return None
    
    def get_database_credentials(self, database: str) -> Optional[Dict[str, str]]:
        """
        Get database credentials
        
        Args:
            database: Database name (e.g., "postgresql", "redis")
        
        Returns:
            Dictionary with host, port, username, password
        """
        try:
            path = f"{self.secret_prefix}/databases/{database}"
            response = self.client.secrets.kv.v2.read_secret_version(path=path)
            return response["data"]["data"]
        except Exception as e:
            print(f"Error retrieving {database} credentials: {e}")
            return None
    
    def rotate_api_key(self, service: str, new_key: str) -> bool:
        """
        Rotate an API key
        
        Args:
            service: Service name
            new_key: New API key
        
        Returns:
            True if successful
        """
        try:
            path = f"{self.secret_prefix}/api-keys/{service}"
            
            # Read existing secret to preserve metadata
            existing = self.client.secrets.kv.v2.read_secret_version(path=path)
            secret_data = existing["data"]["data"]
            
            # Update with new key
            secret_data["api_key"] = new_key
            secret_data["rotated_at"] = str(datetime.utcnow())
            
            # Write back
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data
            )
            
            # Clear cache
            self.get_api_key.cache_clear()
            
            return True
        except Exception as e:
            print(f"Error rotating {service} API key: {e}")
            return False


# Example usage in an OSINT module
class ShodanModule:
    """Example OSINT module using Vault for credentials"""
    
    def __init__(self):
        """Initialize Shodan module with Vault credentials"""
        self.vault_manager = OSINTVaultManager()
        self.api_key = self.vault_manager.get_api_key("shodan")
        
        if not self.api_key:
            raise ValueError("Shodan API key not found in Vault")
    
    def search(self, query: str):
        """Search Shodan with query"""
        # Use self.api_key for API calls
        print(f"Searching Shodan with query: {query}")
        # ... actual implementation ...
```

---

## Rotation Policies

### Automatic Rotation

Configure automatic rotation for dynamic secrets:

```python
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    allowed_roles="readonly" \
    connection_url="postgresql://{{username}}:{{password}}@localhost:5432/osint" \
    username="vault-admin" \
    password="vault-password"

# Create role with rotation
vault write database/roles/readonly \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

### Manual Rotation Script

```python
#!/usr/bin/env python3
"""
Rotate all API keys stored in Vault
"""

import hvac
import os
from datetime import datetime, timedelta

def rotate_api_keys():
    """Rotate API keys that are older than 90 days"""
    client = hvac.Client(
        url=os.getenv("VAULT_ADDR"),
        token=os.getenv("VAULT_TOKEN")
    )
    
    # List all API keys
    keys = client.secrets.kv.v2.list_secrets(path="passive-osint/api-keys")
    
    for key in keys["data"]["keys"]:
        path = f"passive-osint/api-keys/{key}"
        secret = client.secrets.kv.v2.read_secret_version(path=path)
        
        # Check rotation date
        rotated_at = secret["data"]["data"].get("rotated_at")
        if rotated_at:
            last_rotation = datetime.fromisoformat(rotated_at)
            if datetime.utcnow() - last_rotation > timedelta(days=90):
                print(f"⚠️ API key for {key} needs rotation (last rotated {rotated_at})")

if __name__ == "__main__":
    rotate_api_keys()
```

---

## Audit Logging

### Enable Audit Logging

```bash
# Enable file audit backend
vault audit enable file file_path=/var/log/vault/audit.log

# Enable syslog audit backend
vault audit enable syslog
```

### Query Audit Logs

```python
import json

def analyze_vault_audit_log(log_file: str):
    """Analyze Vault audit logs for security events"""
    with open(log_file) as f:
        for line in f:
            entry = json.loads(line)
            
            # Check for failed authentication attempts
            if entry.get("error") and "auth" in entry.get("type", ""):
                print(f"Failed auth attempt: {entry['request']['path']}")
            
            # Check for secret access
            if entry.get("type") == "response" and "secret" in entry.get("request", {}).get("path", ""):
                print(f"Secret accessed: {entry['request']['path']} by {entry['auth']['display_name']}")
```

---

## Best Practices

### Security

1. **Use TLS in Production**: Always use HTTPS for Vault connections
2. **Rotate Credentials Regularly**: Implement 90-day rotation for API keys
3. **Use AppRole for Applications**: Never hardcode tokens in code
4. **Enable Audit Logging**: Monitor all access to secrets
5. **Use Namespaces**: Separate secrets by environment (dev/staging/prod)

### Performance

1. **Cache Secrets**: Use `@lru_cache` to avoid repeated Vault calls
2. **Use Token Renewal**: Renew tokens before expiration
3. **Batch Operations**: Retrieve multiple secrets in one call when possible

### Operations

1. **Backup Vault Data**: Regular snapshots of Vault storage
2. **Test Disaster Recovery**: Practice unsealing and restoring
3. **Monitor Vault Health**: Alert on seal status and auth failures
4. **Document Secret Paths**: Maintain inventory of all secrets

---

## Troubleshooting

### Common Issues

#### Authentication Failed

```bash
# Check Vault status
vault status

# Verify token is valid
vault token lookup

# Check AppRole credentials
vault read auth/approle/role/passive-osint
```

#### Connection Refused

```bash
# Check Vault is running
ps aux | grep vault

# Test connectivity
curl -k https://vault.example.com:8200/v1/sys/health

# Check firewall rules
telnet vault.example.com 8200
```

#### Secret Not Found

```bash
# List secrets at path
vault kv list secret/passive-osint/api-keys

# Check permissions
vault token capabilities secret/data/passive-osint/api-keys/shodan
```

### Debug Mode

```python
import logging
import hvac

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

client = hvac.Client(url=os.getenv("VAULT_ADDR"))
# ... debug output will show all API calls ...
```

---

## Additional Resources

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [hvac Python Library](https://hvac.readthedocs.io/)
- [Vault Security Best Practices](https://learn.hashicorp.com/tutorials/vault/production-hardening)
- [Vault Reference Architecture](https://learn.hashicorp.com/tutorials/vault/reference-architecture)

---

## Support

For issues or questions:
1. Check the [troubleshooting section](#troubleshooting)
2. Review Vault audit logs
3. Open an issue with logs and error messages
4. Consult the [SECURITY.md](../SECURITY.md) for security-related questions
