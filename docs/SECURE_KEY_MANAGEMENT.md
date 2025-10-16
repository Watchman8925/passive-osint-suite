# Secure Key Management Guide

This guide explains how to securely manage cryptographic keys for the Passive OSINT Suite, particularly the audit trail signing keys.

## Overview

The Passive OSINT Suite uses Ed25519 cryptographic signatures to ensure audit trail integrity. Private keys must be protected and never committed to version control.

## Key Types

### Audit Signing Key (Ed25519)
- **Purpose**: Sign audit trail entries for tamper-evident logging
- **Algorithm**: Ed25519 (elliptic curve digital signature)
- **Format**: PEM-encoded PKCS#8
- **Storage**: Environment variable or secure file storage

## Security Best Practices

### ✅ DO

1. **Use Environment Variables**
   - Store private keys as environment variables in production
   - Use base64-encoded PEM format for easy transport
   - Load from secret managers (AWS Secrets Manager, Azure Key Vault, etc.)

2. **Rotate Keys Regularly**
   - Establish a key rotation policy (e.g., every 90 days)
   - Keep old public keys for signature verification of historical data
   - Document key rotation events

3. **Restrict Access**
   - Limit who can access private keys
   - Use IAM policies for secret manager access
   - Log all key access attempts

4. **Backup Securely**
   - Backup keys to encrypted storage
   - Use multiple backup locations
   - Test backup restoration procedures

### ❌ DON'T

1. **Never Commit to Git**
   - Don't commit private keys to any repository (public or private)
   - Don't commit `.env` files containing keys
   - Don't store keys in Docker images

2. **Never Share Unnecessarily**
   - Don't email private keys
   - Don't store in shared documents
   - Don't log private keys

3. **Never Use Weak Permissions**
   - Don't set file permissions to 777 or 666
   - Don't store in publicly readable locations
   - Don't use weak encryption for storage

## Setup Instructions

### Development Environment

1. **Generate a New Key**
   ```bash
   python3 << 'EOF'
   from cryptography.hazmat.primitives.asymmetric import ed25519
   from cryptography.hazmat.primitives import serialization
   import base64
   
   # Generate new Ed25519 key pair
   private_key = ed25519.Ed25519PrivateKey.generate()
   
   # Export private key as base64-encoded PEM
   private_pem = private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption()
   )
   encoded_private = base64.b64encode(private_pem).decode()
   
   # Export public key
   public_pem = private_key.public_key().public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
   )
   
   print("=== Private Key (KEEP SECRET) ===")
   print(f"AUDIT_SIGNING_KEY={encoded_private}")
   print("\n=== Public Key (can be shared) ===")
   print(public_pem.decode())
   EOF
   ```

2. **Add to .env File**
   ```bash
   # Create .env file if it doesn't exist
   cp .env.example .env
   
   # Add the generated key (replace with your actual key)
   echo "AUDIT_SIGNING_KEY=<your_base64_encoded_key_here>" >> .env
   ```

3. **Set File Permissions**
   ```bash
   chmod 600 .env  # Owner read/write only
   ```

4. **Verify .gitignore**
   Ensure `.env` is in `.gitignore`:
   ```bash
   grep -q "^\.env$" .gitignore || echo ".env" >> .gitignore
   ```

### Production Environment

#### Option 1: Secret Manager (Recommended)

**AWS Secrets Manager**
```bash
# Store the key
aws secretsmanager create-secret \
    --name osint-suite/audit-signing-key \
    --secret-string "<your_base64_encoded_key>"

# Retrieve at runtime (in application startup)
export AUDIT_SIGNING_KEY=$(aws secretsmanager get-secret-value \
    --secret-id osint-suite/audit-signing-key \
    --query SecretString \
    --output text)
```

**Azure Key Vault**
```bash
# Store the key
az keyvault secret set \
    --vault-name osint-suite-vault \
    --name audit-signing-key \
    --value "<your_base64_encoded_key>"

# Retrieve at runtime
export AUDIT_SIGNING_KEY=$(az keyvault secret show \
    --vault-name osint-suite-vault \
    --name audit-signing-key \
    --query value \
    --output tsv)
```

**HashiCorp Vault**
```bash
# Store the key
vault kv put secret/osint-suite/audit-signing-key value="<your_base64_encoded_key>"

# Retrieve at runtime
export AUDIT_SIGNING_KEY=$(vault kv get -field=value secret/osint-suite/audit-signing-key)
```

#### Option 2: Environment Variables

For Docker/Kubernetes deployments:

**Docker Compose**
```yaml
services:
  osint-suite:
    environment:
      - AUDIT_SIGNING_KEY=${AUDIT_SIGNING_KEY}
    env_file:
      - .env.production  # Never commit this file
```

**Kubernetes Secret**
```bash
# Create secret
kubectl create secret generic osint-suite-keys \
    --from-literal=audit-signing-key='<your_base64_encoded_key>'

# Reference in deployment
apiVersion: v1
kind: Pod
metadata:
  name: osint-suite
spec:
  containers:
  - name: app
    env:
    - name: AUDIT_SIGNING_KEY
      valueFrom:
        secretKeyRef:
          name: osint-suite-keys
          key: audit-signing-key
```

#### Option 3: Encrypted File

For traditional deployments:

```bash
# Encrypt the key file
openssl enc -aes-256-cbc -salt \
    -in audit_key.pem \
    -out audit_key.pem.enc \
    -k <strong_password>

# Decrypt at runtime
export AUDIT_SIGNING_KEY=$(openssl enc -aes-256-cbc -d \
    -in audit_key.pem.enc \
    -k <strong_password> | base64 -w 0)
```

## Key Rotation Procedure

1. **Generate New Key**
   ```bash
   python3 generate_audit_key.py > new_key.txt
   ```

2. **Update Secret Storage**
   - Update environment variable or secret manager
   - Keep old public key for verification

3. **Deploy New Key**
   - Rolling deployment to update all instances
   - Verify new key is being used

4. **Archive Old Key**
   - Save old public key to `audit_public_keys/` directory
   - Document rotation date and reason
   - Keep for historical signature verification

5. **Update Documentation**
   - Record key rotation in security log
   - Update compliance documentation

## Verification

### Test Key Loading

```bash
# Set test key
export AUDIT_SIGNING_KEY="<your_key>"

# Run verification script
python3 << 'EOF'
from security.audit_trail import AuditTrail
import os

# Create audit trail instance
trail = AuditTrail()

# Log a test operation
entry_id = trail.log_operation(
    operation="test_key_loading",
    actor="system",
    target="test",
    metadata={"purpose": "key verification"}
)

print(f"✅ Successfully logged entry: {entry_id}")
print("✅ Key is working correctly")

# Verify the entry
entries = trail.search_entries(operation="test_key_loading", limit=1)
if entries and trail.verify_entry(entries[0]):
    print("✅ Signature verification passed")
else:
    print("❌ Signature verification failed")
EOF
```

### Verify No Keys in Repository

```bash
# Check for accidentally committed keys
git grep -i "BEGIN.*PRIVATE KEY" || echo "✅ No private keys found"

# Check current working directory
find . -name "*.pem" -o -name "*.key" | grep -v ".git" || echo "✅ No key files in working directory"
```

## Troubleshooting

### Key Not Loading

**Symptom**: Application generates new key on every start

**Solutions**:
1. Check environment variable is set: `echo $AUDIT_SIGNING_KEY`
2. Verify base64 encoding is correct
3. Check file permissions if using file storage
4. Review application logs for specific errors

### Signature Verification Failing

**Symptom**: Audit entries fail signature verification

**Possible Causes**:
1. Wrong public key being used
2. Audit entry corrupted
3. Key rotation in progress
4. Clock skew between systems

### Permission Denied

**Symptom**: Cannot read key file

**Solution**:
```bash
# Fix file permissions
chmod 600 /path/to/key.pem
chown $USER:$USER /path/to/key.pem
```

## Compliance Notes

### Audit Requirements
- Document all key generation events
- Log all key access attempts
- Maintain key rotation schedule
- Keep historical public keys for signature verification

### Regulatory Standards
- **PCI DSS**: Rotate keys at least annually
- **HIPAA**: Implement key escrow procedures
- **SOC 2**: Document key management procedures
- **ISO 27001**: Implement cryptographic key lifecycle management

## Additional Resources

- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Ed25519 Specification](https://ed25519.cr.yp.to/)
- [cryptography library documentation](https://cryptography.io/)

## Support

For questions about key management:
1. Check this documentation first
2. Review security incident reports in `docs/`
3. Contact the security team
4. Open an issue on GitHub (DO NOT include private keys)

---
**Last Updated**: 2025-10-15  
**Document Owner**: Security Team
