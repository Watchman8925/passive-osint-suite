#!/bin/bash
#
# Repository History Cleanup Script
# 
# This script provides safe, interactive instructions for cleaning sensitive data
# from git history using BFG Repo-Cleaner or git-filter-repo.
#
# WARNING: This operation rewrites git history and requires force-push.
# Coordinate with all contributors before running.
#
# Usage: ./scripts/clean_history.sh [--scan-only]
#

set -e

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_ONLY=false
BACKUP_DIR="${HOME}/git-history-backup-$(date +%Y%m%d-%H%M%S)"

# Parse arguments
if [[ "$1" == "--scan-only" ]]; then
    SCAN_ONLY=true
fi

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Git History Cleanup Tool${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Function to detect large files
detect_large_files() {
    echo -e "${YELLOW}Scanning for large files (>1MB) in git history...${NC}"
    echo ""
    
    git rev-list --objects --all |
        git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' |
        awk '/^blob/ {if ($3 > 1048576) print $3, $4}' |
        sort -nr |
        head -20 |
        numfmt --to=iec-i --suffix=B --padding=7 || true
    
    echo ""
}

# Function to detect potential secrets in filenames
detect_secret_patterns() {
    echo -e "${YELLOW}Scanning for files with potential secret patterns...${NC}"
    echo ""
    
    # Patterns that commonly indicate secrets
    local patterns=(
        "*.pem"
        "*.key"
        "*.p12"
        "*.pfx"
        "*.jks"
        "*.keystore"
        "*secret*"
        "*password*"
        "*credentials*"
        "*.env"
        ".env.*"
        "*token*"
        "*apikey*"
        "id_rsa*"
        "id_dsa*"
        "id_ecdsa*"
        "id_ed25519*"
    )
    
    for pattern in "${patterns[@]}"; do
        echo -e "${BLUE}Checking pattern: ${pattern}${NC}"
        git log --all --pretty=format: --name-only --diff-filter=A |
            sort -u |
            grep -i "${pattern}" || true
    done
    
    echo ""
}

# Function to check if tools are available
check_tools() {
    echo -e "${YELLOW}Checking for cleanup tools...${NC}"
    echo ""
    
    local bfg_available=false
    local filter_repo_available=false
    
    if command -v bfg &> /dev/null; then
        echo -e "${GREEN}✓ BFG Repo-Cleaner found${NC}"
        bfg_available=true
    else
        echo -e "${RED}✗ BFG Repo-Cleaner not found${NC}"
        echo "  Install: brew install bfg  # macOS"
        echo "  Or download: https://rtyley.github.io/bfg-repo-cleaner/"
    fi
    
    if command -v git-filter-repo &> /dev/null; then
        echo -e "${GREEN}✓ git-filter-repo found${NC}"
        filter_repo_available=true
    else
        echo -e "${RED}✗ git-filter-repo not found${NC}"
        echo "  Install: pip install git-filter-repo"
        echo "  Or: brew install git-filter-repo  # macOS"
    fi
    
    echo ""
    
    if ! $bfg_available && ! $filter_repo_available; then
        echo -e "${RED}ERROR: No cleanup tools available. Please install BFG or git-filter-repo.${NC}"
        exit 1
    fi
}

# Function to create backup
create_backup() {
    echo -e "${YELLOW}Creating backup of repository...${NC}"
    echo "Backup location: ${BACKUP_DIR}"
    echo ""
    
    mkdir -p "${BACKUP_DIR}"
    git clone --mirror "${REPO_ROOT}" "${BACKUP_DIR}/repo.git"
    
    echo -e "${GREEN}✓ Backup created successfully${NC}"
    echo "To restore: git clone ${BACKUP_DIR}/repo.git restored-repo"
    echo ""
}

# Function to show cleanup instructions for BFG
show_bfg_instructions() {
    cat << 'EOF'

========================================
BFG Repo-Cleaner Instructions
========================================

1. CREATE A BACKUP FIRST (done above)

2. Remove sensitive files by name:
   bfg --delete-files '{secrets.txt,*.key,*.pem}' --no-blob-protection .

3. Replace sensitive strings in all files:
   echo "PASSWORD1" > passwords.txt
   echo "API_KEY_123" >> passwords.txt
   bfg --replace-text passwords.txt --no-blob-protection .

4. Remove large files (>100MB):
   bfg --strip-blobs-bigger-than 100M --no-blob-protection .

5. Clean up the repository:
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive

6. VERIFY the changes:
   git log --all --oneline --graph
   git log --all --stat

7. Force push (COORDINATE WITH TEAM FIRST):
   git push origin --force --all
   git push origin --force --tags

EOF
}

# Function to show cleanup instructions for git-filter-repo
show_filter_repo_instructions() {
    cat << 'EOF'

========================================
git-filter-repo Instructions
========================================

1. CREATE A BACKUP FIRST (done above)

2. Remove files by path:
   git filter-repo --path secrets.txt --invert-paths
   git filter-repo --path-glob '*.key' --invert-paths

3. Replace sensitive strings:
   git filter-repo --replace-text <(echo "PASSWORD1==>***REMOVED***")

4. Remove files by size (>100MB):
   git filter-repo --strip-blobs-bigger-than 100M

5. VERIFY the changes:
   git log --all --oneline --graph
   git log --all --stat

6. Add remote back (filter-repo removes remotes):
   git remote add origin <original-remote-url>

7. Force push (COORDINATE WITH TEAM FIRST):
   git push origin --force --all
   git push origin --force --tags

EOF
}

# Function to show coordination instructions
show_coordination_instructions() {
    cat << 'EOF'

========================================
IMPORTANT: Coordination Steps
========================================

Before force-pushing, you MUST:

1. NOTIFY all contributors via:
   - GitHub issue or discussion
   - Team chat/email
   - Pull request

2. ENSURE everyone has:
   - Pushed all their changes
   - No pending work in progress
   - Saved any important branches

3. AFTER force push, all contributors must:
   
   a) Backup their local work:
      git branch backup-branch-name
   
   b) Reset their local repository:
      git fetch origin
      git reset --hard origin/main
      git clean -fdx
   
   c) Rebase their feature branches:
      git checkout feature-branch
      git rebase origin/main
   
   d) If rebase fails, they may need to:
      git checkout feature-branch
      git reset --hard backup-branch-name
      git rebase --onto origin/main <old-base-commit> feature-branch

4. CREATE a notification template:

---
Subject: [ACTION REQUIRED] Git History Rewrite on [DATE]

Team,

We will be rewriting git history to remove sensitive data on [DATE] at [TIME].

BEFORE the rewrite:
- Push all your changes
- Finish any pending work
- Create backups: git branch backup-$(date +%Y%m%d)

AFTER the rewrite:
- git fetch origin
- git reset --hard origin/main
- Rebase your feature branches

Detailed instructions: [LINK TO THIS FILE]

Questions? Reply to this message.
---

5. ROTATE all exposed credentials:
   - API keys
   - Passwords
   - Tokens
   - Certificates

6. DOCUMENT the cleanup:
   - Add entry to CHANGELOG
   - Update SECURITY.md if needed
   - Close related security issues

EOF
}

# Function to show verification steps
show_verification_steps() {
    cat << 'EOF'

========================================
Verification Steps
========================================

After cleanup, verify that secrets are removed:

1. Re-scan with gitleaks:
   gitleaks detect --source . --verbose

2. Search for specific strings:
   git log --all -S "SECRET_STRING" --pretty=format:"%H %s"
   git log --all -G "SECRET_PATTERN" --pretty=format:"%H %s"

3. Check file was removed:
   git log --all --full-history --pretty=format:"%H" -- path/to/secret.txt

4. Verify repository size:
   du -sh .git/

5. Check all branches:
   git branch -r
   for branch in $(git branch -r); do
       echo "Checking $branch"
       git log $branch --oneline | head -5
   done

EOF
}

# Main execution
main() {
    cd "${REPO_ROOT}"
    
    echo -e "${YELLOW}Repository root: ${REPO_ROOT}${NC}"
    echo ""
    
    # Run detection
    detect_large_files
    detect_secret_patterns
    
    if $SCAN_ONLY; then
        echo -e "${GREEN}Scan complete. Use without --scan-only to proceed with cleanup.${NC}"
        exit 0
    fi
    
    # Check for cleanup tools
    check_tools
    
    # Confirm with user
    echo -e "${RED}WARNING: This operation will rewrite git history!${NC}"
    echo -e "${RED}This requires coordination with all contributors.${NC}"
    echo ""
    echo -e "${YELLOW}Have you:${NC}"
    echo "  1. Read the coordination instructions?"
    echo "  2. Notified all contributors?"
    echo "  3. Ensured everyone has pushed their work?"
    echo ""
    read -p "Continue? (type 'yes' to proceed): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${YELLOW}Aborted. No changes made.${NC}"
        exit 0
    fi
    
    # Create backup
    create_backup
    
    # Show instructions
    echo ""
    echo -e "${BLUE}Choose your cleanup method:${NC}"
    echo "1. BFG Repo-Cleaner (faster, recommended for simple cases)"
    echo "2. git-filter-repo (more powerful, recommended for complex cases)"
    echo "3. Show coordination instructions only"
    echo ""
    read -p "Enter choice (1-3): " choice
    
    case $choice in
        1)
            show_bfg_instructions
            ;;
        2)
            show_filter_repo_instructions
            ;;
        3)
            show_coordination_instructions
            show_verification_steps
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
    
    show_coordination_instructions
    show_verification_steps
    
    echo ""
    echo -e "${GREEN}Instructions displayed above.${NC}"
    echo -e "${GREEN}Backup location: ${BACKUP_DIR}${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Follow the coordination steps before force-pushing!${NC}"
}

# Run main function
main
