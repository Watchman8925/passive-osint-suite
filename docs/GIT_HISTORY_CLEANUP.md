# Git History Cleanup Instructions

## ⚠️ CRITICAL: Remove Committed Private Key from Git History

This document provides step-by-step instructions for removing the compromised private key from the entire git history. This operation **MUST** be completed by a repository administrator.

## Prerequisites

- Admin access to the repository
- Backup of the repository (just in case)
- Notification to all contributors that a force push will occur
- Access to a local clone of the repository

## Overview

The private key `config/audit_ed25519_key.pem` was committed to the repository and must be completely removed from all branches and tags. Simply deleting the file is not sufficient as it remains in git history.

## Option 1: Using git-filter-repo (Recommended)

`git-filter-repo` is the officially recommended tool by Git for rewriting history.

### Installation

```bash
# macOS
brew install git-filter-repo

# Linux (Ubuntu/Debian)
sudo apt-get install git-filter-repo

# Linux (other)
pip3 install git-filter-repo

# Or download directly
curl -O https://raw.githubusercontent.com/newren/git-filter-repo/main/git-filter-repo
chmod +x git-filter-repo
sudo mv git-filter-repo /usr/local/bin/
```

### Execution Steps

1. **Create a fresh clone** (important - don't use existing clone):
   ```bash
   git clone https://github.com/Watchman8925/passive-osint-suite.git
   cd passive-osint-suite
   ```

2. **Backup the repository** (optional but recommended):
   ```bash
   cd ..
   cp -r passive-osint-suite passive-osint-suite-backup
   cd passive-osint-suite
   ```

3. **Run git-filter-repo to remove the key**:
   ```bash
   # Remove the specific file from all history
   git filter-repo --path config/audit_ed25519_key.pem --invert-paths
   ```

4. **Verify the file is removed**:
   ```bash
   # This should return nothing
   git log --all --full-history -- config/audit_ed25519_key.pem
   
   # This should also return nothing
   git grep -i "BEGIN.*PRIVATE KEY"
   ```

5. **Re-add the remote** (git-filter-repo removes it):
   ```bash
   git remote add origin https://github.com/Watchman8925/passive-osint-suite.git
   ```

6. **Force push all branches**:
   ```bash
   # Push all branches
   git push origin --force --all
   
   # Push all tags
   git push origin --force --tags
   ```

7. **Notify all collaborators**:
   - They must delete their local clones
   - They must create fresh clones from the rewritten repository
   - Old clones will have conflicts if they try to pull

### Post-Cleanup Verification

```bash
# Clone fresh copy to verify
cd /tmp
git clone https://github.com/Watchman8925/passive-osint-suite.git verify
cd verify

# Verify file is gone from history
git log --all --full-history -- config/audit_ed25519_key.pem
# Should output nothing

# Search for any remaining keys
git grep -i "BEGIN.*PRIVATE KEY"
# Should output nothing

# Check specific commit that originally added the key
git show fe3be9e:config/audit_ed25519_key.pem
# Should fail with error

echo "✅ Verification complete!"
```

## Option 2: Using BFG Repo-Cleaner (Alternative)

BFG is faster but less flexible than git-filter-repo.

### Installation

```bash
# Download BFG
wget https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar

# Or using brew on macOS
brew install bfg
```

### Execution Steps

1. **Create a fresh clone** (bare clone):
   ```bash
   git clone --mirror https://github.com/Watchman8925/passive-osint-suite.git
   cd passive-osint-suite.git
   ```

2. **Run BFG to remove the key**:
   ```bash
   # If using jar file
   java -jar ../bfg-1.14.0.jar --delete-files audit_ed25519_key.pem
   
   # If using brew install
   bfg --delete-files audit_ed25519_key.pem
   ```

3. **Clean up and garbage collect**:
   ```bash
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   ```

4. **Force push**:
   ```bash
   git push --force
   ```

## Option 3: GitHub's Built-in Tool (Easiest)

GitHub provides a tool for removing sensitive data, though it may take time to process.

1. Go to repository settings
2. Navigate to "Security" → "Secret scanning"
3. If the key was detected, follow the remediation steps
4. Alternatively, contact GitHub support with details of the commit containing the key

## Post-Cleanup Actions

### 1. Verify Cleanup Across All Platforms

```bash
# Check GitHub
# - Browse to https://github.com/Watchman8925/passive-osint-suite/commits
# - Search for commit fe3be9e
# - Verify file is not visible

# Check all forks (if any exist)
# - Forks may still contain the key
# - Contact fork owners or delete and recreate forks
```

### 2. Notify All Contributors

Send this message to all contributors:

```
IMPORTANT: Repository History Rewritten

We have removed a compromised private key from the repository history.
All contributors must:

1. Delete your local clone: rm -rf passive-osint-suite
2. Clone fresh copy: git clone https://github.com/Watchman8925/passive-osint-suite.git
3. Do NOT attempt to merge or pull from old clones

If you have uncommitted changes, save them elsewhere before deleting.

Any attempts to push from old clones will fail and must not be force-pushed
as this would restore the compromised key.
```

### 3. Clean Up GitHub Actions Cache

```bash
# GitHub Actions caches may contain old versions
# Clear all caches through the GitHub UI:
# Settings → Actions → Caches → Delete all caches
```

### 4. Regenerate Compromised Key

```bash
# Generate new key
python scripts/generate_audit_key.py

# Store in secret manager or .env file
# Update all deployments with new key
```

### 5. Update Documentation

- [x] Create security incident report (docs/SECURITY_INCIDENT_2025-10-15.md)
- [x] Update .gitignore to prevent future issues
- [x] Document secure key management practices
- [ ] Mark historical audit logs as "potentially compromised"
- [ ] Update compliance documentation

## Troubleshooting

### "Cannot force push" Error

**Problem**: Force push is rejected by branch protection rules

**Solution**:
1. Temporarily disable branch protection in repository settings
2. Perform the force push
3. Re-enable branch protection

### "Non-fast-forward" Error

**Problem**: Old history conflicts with new history

**Solution**:
```bash
# Use --force flag (not --force-with-lease)
git push origin --force --all
```

### Contributors Report Conflicts

**Problem**: Contributors trying to pull/push from old clones

**Solution**:
- They MUST delete old clones and create fresh ones
- Do NOT attempt to merge or rebase
- Save uncommitted work separately before deleting

### Forks Still Contain the Key

**Problem**: Forked repositories weren't cleaned

**Solutions**:
1. Contact fork owners to delete and re-fork
2. If you own the forks, delete and recreate them
3. Use GitHub's takedown process if unauthorized forks exist

## Verification Checklist

After completing the cleanup, verify:

- [ ] File is removed from all branches
- [ ] File is removed from all tags
- [ ] Commit history doesn't show the file
- [ ] `git log --all -- config/audit_ed25519_key.pem` returns nothing
- [ ] `git grep "BEGIN.*PRIVATE KEY"` returns nothing
- [ ] All contributors have fresh clones
- [ ] GitHub Actions caches cleared
- [ ] New signing key generated and deployed
- [ ] Documentation updated
- [ ] Incident report filed
- [ ] Stakeholders notified

## Timeline Estimate

- Preparation and backup: 10 minutes
- Running git-filter-repo: 5-10 minutes (depends on repo size)
- Force push: 5 minutes
- Verification: 10 minutes
- Contributor notification: 1 day (for coordination)
- **Total**: ~2 hours of work + 1 day for coordination

## Support

For issues during cleanup:
1. Check git-filter-repo documentation: https://github.com/newren/git-filter-repo
2. Review GitHub's guide: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
3. Contact GitHub support if needed

## References

- [git-filter-repo Manual](https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [GitHub: Removing Sensitive Data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [OWASP: Removing Secrets from Git](https://owasp.org/www-community/attacks/Forced_browsing#removing-secrets-from-git)

---
**Status**: Awaiting admin execution  
**Created**: 2025-10-15  
**Priority**: CRITICAL
