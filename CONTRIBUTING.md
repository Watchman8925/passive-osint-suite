# Contributing to Passive OSINT Suite

Thank you for your interest in contributing to the Passive OSINT Suite! This document provides guidelines and best practices for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Writing Safe Modules](#writing-safe-modules)
- [Testing](#testing)
- [Code Style](#code-style)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Secret Management](#secret-management)
- [Force-Push Coordination](#force-push-coordination)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please be respectful and professional in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/passive-osint-suite.git
   cd passive-osint-suite
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Watchman8925/passive-osint-suite.git
   ```

4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Node.js 20 or higher (for web interface)
- Docker (optional, for containerized development)

### Install Dependencies

```bash
# Python dependencies
pip install -r requirements.txt

# Development dependencies
pip install -r requirements_minimal.txt
pip install pytest black ruff mypy

# Pre-commit hooks
pre-commit install
```

### Run Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_safety_helpers.py

# Run with coverage
pytest --cov=src --cov=modules
```

## Writing Safe Modules

All OSINT modules should use the shared safety helpers from `src.passive_osint_common.safety`. This ensures consistent error handling, timeouts, and logging across the codebase.

### Using Safety Helpers

```python
from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_valid_domain,
    is_positive_integer,
)

# Configure module logger
logger = configure_logger(__name__)

# Use input validation decorator
@input_validation(
    domain=is_valid_domain,
    limit=lambda x: isinstance(x, int) and 1 <= x <= 100
)
@handle_exceptions(default_return={"status": "error", "results": []})
def search_domain(domain: str, limit: int = 10):
    """
    Search for domain information with safety wrappers.
    
    Args:
        domain: Valid domain name
        limit: Number of results (1-100)
    
    Returns:
        Dictionary with status and results
    """
    logger.info(f"Searching domain: {domain}")
    
    # Use safe_request instead of requests.get()
    response = safe_request(
        f"https://api.example.com/domain/{domain}",
        timeout=30,
        max_retries=3
    )
    
    if not response or not response.ok:
        logger.error(f"API request failed: {domain}")
        return {"status": "error", "results": []}
    
    data = response.json()
    return {"status": "success", "results": data[:limit]}
```

### Key Safety Principles

1. **Always use `safe_request`** instead of raw `requests` calls
   - Enforces timeouts (default 30s)
   - Implements retry logic with exponential backoff
   - Handles rate limiting
   - Logs errors consistently

2. **Validate inputs** with `@input_validation` decorator
   - Prevents invalid data from reaching your code
   - Provides clear error messages
   - Use built-in validators: `is_valid_domain`, `is_valid_url`, `is_valid_ip`, etc.

3. **Handle exceptions** with `@handle_exceptions` decorator
   - Returns structured error responses
   - Logs exceptions with full traceback
   - Prevents crashes from propagating to users

4. **Use structured logging** with `configure_logger`
   - Consistent log format across modules
   - Proper log levels (DEBUG, INFO, WARNING, ERROR)
   - Include context in log messages

### Module Template

```python
#!/usr/bin/env python3
"""
Module Name: Brief Description

This module provides functionality for [purpose].
"""

from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_non_empty_string,
)

# Configure logger
logger = configure_logger(__name__)


class MyOSINTModule:
    """OSINT module for [purpose]"""
    
    def __init__(self, api_key: str = None):
        """
        Initialize module.
        
        Args:
            api_key: Optional API key for authentication
        """
        self.api_key = api_key
        logger.info("MyOSINTModule initialized")
    
    @input_validation(query=is_non_empty_string)
    @handle_exceptions(default_return={"status": "error"})
    def search(self, query: str):
        """
        Search for information.
        
        Args:
            query: Search query (non-empty string)
        
        Returns:
            Dictionary with status and results
        """
        logger.debug(f"Searching for: {query}")
        
        # Implementation here
        response = safe_request(
            f"https://api.example.com/search",
            params={"q": query},
            timeout=30
        )
        
        if not response or not response.ok:
            return {"status": "error", "message": "API request failed"}
        
        return {"status": "success", "data": response.json()}
```

## Testing

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Use descriptive test names: `test_function_name_expected_behavior`

### Test Example

```python
import pytest
from modules.my_module import MyOSINTModule

def test_search_valid_input():
    """Test search with valid input"""
    module = MyOSINTModule()
    result = module.search("test query")
    assert result["status"] in ["success", "error"]

def test_search_empty_input():
    """Test search rejects empty input"""
    module = MyOSINTModule()
    with pytest.raises(ValueError):
        module.search("")
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_my_module.py

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=modules --cov-report=html
```

## Code Style

### Python Style Guide

- Follow PEP 8 style guide
- Use Black for code formatting: `black .`
- Use Ruff for linting: `ruff check .`
- Use mypy for type checking: `mypy modules/`

### Formatting Commands

```bash
# Format code
black .

# Check linting
ruff check .

# Fix auto-fixable issues
ruff check --fix .

# Type checking
mypy modules/ --ignore-missing-imports
```

### Documentation

- Use docstrings for all public functions and classes
- Follow Google-style docstring format
- Include type hints in function signatures

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(modules): add DNS intelligence module

Implement DNS intelligence module with safety wrappers and comprehensive error handling.

Closes #123

fix(safety): handle timeout exceptions in safe_request

Ensure timeout exceptions are caught and logged properly.

docs(contributing): update module development guidelines

Add section on using safety helpers with examples.
```

## Pull Request Process

1. **Update your branch** with latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests** and ensure they pass:
   ```bash
   pytest
   black --check .
   ruff check .
   ```

3. **Create pull request** with:
   - Clear title describing the change
   - Description of what changed and why
   - Link to related issues
   - Screenshots for UI changes
   - Test results

4. **Address review comments** by:
   - Making requested changes
   - Pushing to the same branch
   - Responding to reviewer questions

5. **Squash commits** if requested:
   ```bash
   git rebase -i upstream/main
   git push --force-with-lease
   ```

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow guidelines
- [ ] No secrets or credentials in code
- [ ] Safety helpers used for all network calls
- [ ] Input validation added for public functions

## Secret Management

### Never Commit Secrets

**Never commit:**
- API keys
- Passwords
- Tokens
- Private keys
- Credentials of any kind

### Use Environment Variables

```python
import os

# Good: Use environment variables
api_key = os.getenv("SHODAN_API_KEY")

# Bad: Hardcoded secrets
api_key = "abc123..."  # DON'T DO THIS!
```

### Removing Secrets from History

If you accidentally commit a secret:

1. **Rotate the credential immediately**
2. **Remove from git history** using `scripts/clean_history.sh`
3. **Report to security team** via SECURITY.md process

See [docs/vault_integration.md](docs/vault_integration.md) for secure credential storage.

## Force-Push Coordination

If repository history needs to be rewritten (e.g., to remove secrets), follow these steps:

### Before Force-Push

1. **Create GitHub issue** announcing the force-push
2. **Notify all contributors** via issue, email, or chat
3. **Set a date/time** for the force-push
4. **Ensure everyone has pushed** their pending work
5. **Create backup** of the repository

### Notification Template

```markdown
# [ACTION REQUIRED] Git History Rewrite - [DATE] at [TIME]

We will be rewriting git history to remove sensitive data.

## Before the rewrite:
- [ ] Push all your changes: `git push`
- [ ] Create a backup branch: `git branch backup-$(date +%Y%m%d)`
- [ ] Save any work in progress

## After the rewrite:
1. Fetch the new history: `git fetch origin`
2. Reset your branch: `git reset --hard origin/main`
3. Clean untracked files: `git clean -fdx`
4. Rebase feature branches: `git rebase origin/main`

## Questions?
Reply to this issue or contact [maintainer email].
```

### After Force-Push

All contributors must:

1. **Backup local work**:
   ```bash
   git branch backup-before-rewrite
   ```

2. **Fetch new history**:
   ```bash
   git fetch origin
   git reset --hard origin/main
   ```

3. **Rebase feature branches**:
   ```bash
   git checkout feature-branch
   git rebase origin/main
   ```

4. **Verify history**:
   ```bash
   git log --oneline -10
   ```

See `scripts/clean_history.sh` for detailed instructions.

## Questions?

- Open an issue for bug reports or feature requests
- Check existing issues before creating new ones
- For security concerns, see [SECURITY.md](SECURITY.md)

## Resources

- [Python Style Guide (PEP 8)](https://pep8.org/)
- [Git Best Practices](https://git-scm.com/book/en/v2)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Vault Integration Guide](docs/vault_integration.md)
- [Enhancement Roadmap](ENHANCEMENT_ROADMAP_2025.md)

---

Thank you for contributing to the Passive OSINT Suite! 🎉
