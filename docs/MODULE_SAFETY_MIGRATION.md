# Module Safety Migration Guide

## Overview

This guide provides instructions for migrating OSINT modules to use the new safety helpers from `src.passive_osint_common.safety`. This is part of Phase 1 of the 2025 Enhancement Roadmap.

## Table of Contents

- [Why Migrate?](#why-migrate)
- [Safety Helpers Overview](#safety-helpers-overview)
- [Migration Steps](#migration-steps)
- [Examples](#examples)
- [Testing](#testing)
- [Rollout Plan](#rollout-plan)

---

## Why Migrate?

The safety helpers provide:

1. **Consistent Timeout Enforcement**: All HTTP requests have proper timeouts
2. **Automatic Retry Logic**: Transient failures are handled gracefully
3. **Rate Limit Detection**: Warns when API limits are approaching
4. **Input Validation**: Prevents invalid data from reaching module logic
5. **Structured Exception Handling**: Consistent error responses
6. **Standardized Logging**: Uniform log format across all modules

### Current State

Most modules inherit from `OSINTUtils` and use `make_request()`:

```python
class MyModule(OSINTUtils):
    def search(self, query):
        response = self.make_request(url)
        # Process response
```

### Target State

Modules should use safety helpers directly:

```python
from src.passive_osint_common.safety import safe_request, input_validation, handle_exceptions

class MyModule(OSINTUtils):
    @input_validation(query=is_non_empty_string)
    @handle_exceptions(default_return={"status": "error"})
    def search(self, query: str):
        response = safe_request(url, timeout=30, max_retries=3)
        # Process response
```

---

## Safety Helpers Overview

### 1. `safe_request()`

Replacement for `requests.get()` and `self.make_request()`:

```python
from src.passive_osint_common.safety import safe_request

# Before
response = requests.get(url)

# After
response = safe_request(url, timeout=30, max_retries=3)
```

**Features**:
- Default 30-second timeout
- Automatic retry on 429, 500, 502, 503, 504
- Exponential backoff
- Rate limit warning
- URL validation

### 2. `@input_validation()`

Validates function inputs before execution:

```python
from src.passive_osint_common.safety import input_validation, is_valid_domain

# Before
def search_domain(self, domain):
    if not domain:
        raise ValueError("Domain required")
    # Function logic

# After
@input_validation(domain=is_valid_domain)
def search_domain(self, domain: str):
    # Function logic - validation happens automatically
```

**Built-in Validators**:
- `is_non_empty_string` - Non-empty string
- `is_valid_url` - Valid URL
- `is_valid_domain` - Valid domain name
- `is_valid_ip` - Valid IP address (v4/v6)
- `is_valid_email` - Valid email address
- `is_positive_integer` - Positive integer
- `is_in_range(min, max)` - Integer in range

### 3. `@handle_exceptions()`

Converts exceptions to structured responses:

```python
from src.passive_osint_common.safety import handle_exceptions

# Before
def search(self, query):
    try:
        # Function logic
        return {"status": "success", "data": data}
    except Exception as e:
        logger.error(f"Error: {e}")
        return {"status": "error", "error": str(e)}

# After
@handle_exceptions(default_return={"status": "error"})
def search(self, query):
    # Function logic
    return {"status": "success", "data": data}
    # Exceptions are caught automatically
```

### 4. `configure_logger()`

Creates standardized logger:

```python
from src.passive_osint_common.safety import configure_logger

# Before
import logging
logger = logging.getLogger(__name__)

# After
logger = configure_logger(__name__)
# Automatically configured with handlers and formatting
```

---

## Migration Steps

### Step 1: Add Imports

Add safety helpers to module imports:

```python
# At top of file
from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_non_empty_string,
    is_valid_domain,
    is_valid_ip,
    is_positive_integer,
)
```

### Step 2: Update Logger

Replace custom logger configuration:

```python
# Before
import logging
logger = logging.getLogger(__name__)

# After
logger = configure_logger(__name__)
```

### Step 3: Add Input Validation

Add validation decorators to public methods:

```python
# Before
def search(self, query, limit=10):
    if not query:
        raise ValueError("Query required")
    if limit < 1 or limit > 100:
        raise ValueError("Limit must be 1-100")
    # Function logic

# After
@input_validation(
    query=is_non_empty_string,
    limit=lambda x: isinstance(x, int) and 1 <= x <= 100
)
def search(self, query: str, limit: int = 10):
    # Function logic - validation automatic
```

### Step 4: Add Exception Handling

Add exception handling decorators:

```python
# Before
def search(self, query):
    try:
        # Function logic
        return {"status": "success", "data": data}
    except Exception as e:
        self.logger.error(f"Search failed: {e}")
        return {"status": "error", "error": str(e)}

# After
@handle_exceptions(default_return={"status": "error"})
def search(self, query):
    # Function logic
    return {"status": "success", "data": data}
    # Exceptions caught automatically
```

### Step 5: Replace HTTP Calls

Replace `make_request()` with `safe_request()`:

```python
# Before
response = self.make_request(url, params=params)

# After
response = safe_request(
    url,
    params=params,
    timeout=30,
    max_retries=3,
    rate_limit_delay=0.5  # Optional
)
```

### Step 6: Test Module

Run module tests to ensure functionality:

```bash
pytest tests/test_my_module.py -v
```

---

## Examples

### Example 1: Simple Search Module

**Before**:
```python
"""Simple search module"""
import requests
from utils.osint_utils import OSINTUtils

class SimpleSearch(OSINTUtils):
    def __init__(self):
        super().__init__()
    
    def search(self, query, limit=10):
        """Search for query"""
        if not query:
            return {"status": "error", "error": "Query required"}
        
        try:
            url = f"https://api.example.com/search"
            response = requests.get(url, params={"q": query, "limit": limit})
            
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            else:
                return {"status": "error", "error": f"Status {response.status_code}"}
        
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return {"status": "error", "error": str(e)}
```

**After**:
```python
"""Simple search module with safety helpers"""
from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_non_empty_string,
    is_positive_integer,
)
from utils.osint_utils import OSINTUtils

# Configure module logger
logger = configure_logger(__name__)

class SimpleSearch(OSINTUtils):
    def __init__(self):
        super().__init__()
    
    @input_validation(
        query=is_non_empty_string,
        limit=lambda x: isinstance(x, int) and 1 <= x <= 100
    )
    @handle_exceptions(default_return={"status": "error"})
    def search(self, query: str, limit: int = 10):
        """
        Search for query with safety wrappers.
        
        Args:
            query: Non-empty search query
            limit: Result limit (1-100)
        
        Returns:
            Dictionary with status and data
        """
        logger.info(f"Searching for: {query}")
        
        url = "https://api.example.com/search"
        response = safe_request(
            url,
            params={"q": query, "limit": limit},
            timeout=30,
            max_retries=3
        )
        
        if not response or not response.ok:
            logger.error(f"API request failed for query: {query}")
            return {"status": "error", "error": "API request failed"}
        
        return {"status": "success", "data": response.json()}
```

**Key Changes**:
1. Added safety helper imports
2. Used `configure_logger()` for logging
3. Added `@input_validation()` decorator
4. Added `@handle_exceptions()` decorator
5. Replaced `requests.get()` with `safe_request()`
6. Added type hints to function signature
7. Improved docstring

### Example 2: Domain Analysis Module

**Before**:
```python
"""Domain analysis module"""
from utils.osint_utils import OSINTUtils
import whois
import dns.resolver

class DomainAnalysis(OSINTUtils):
    def analyze(self, domain):
        """Analyze domain"""
        if not self.validate_input(domain, "domain"):
            return {"status": "error", "error": "Invalid domain"}
        
        try:
            whois_data = whois.whois(domain)
            dns_records = self.get_dns_records(domain)
            
            return {
                "status": "success",
                "whois": whois_data,
                "dns": dns_records
            }
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_dns_records(self, domain):
        """Get DNS records"""
        records = {}
        for record_type in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(a) for a in answers]
            except:
                records[record_type] = []
        return records
```

**After**:
```python
"""Domain analysis module with safety helpers"""
from src.passive_osint_common.safety import (
    input_validation,
    handle_exceptions,
    configure_logger,
    is_valid_domain,
)
from utils.osint_utils import OSINTUtils
import whois
import dns.resolver

# Configure module logger
logger = configure_logger(__name__)

class DomainAnalysis(OSINTUtils):
    @input_validation(domain=is_valid_domain)
    @handle_exceptions(default_return={"status": "error"})
    def analyze(self, domain: str):
        """
        Analyze domain with comprehensive checks.
        
        Args:
            domain: Valid domain name
        
        Returns:
            Dictionary with status, whois, and DNS data
        """
        logger.info(f"Analyzing domain: {domain}")
        
        whois_data = self._get_whois(domain)
        dns_records = self._get_dns_records(domain)
        
        return {
            "status": "success",
            "domain": domain,
            "whois": whois_data,
            "dns": dns_records
        }
    
    @handle_exceptions(default_return={})
    def _get_whois(self, domain: str):
        """Get WHOIS data with error handling"""
        logger.debug(f"Getting WHOIS for {domain}")
        return whois.whois(domain)
    
    @handle_exceptions(default_return={})
    def _get_dns_records(self, domain: str):
        """Get DNS records with error handling"""
        logger.debug(f"Getting DNS records for {domain}")
        
        records = {}
        for record_type in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(a) for a in answers]
            except Exception as e:
                logger.debug(f"DNS {record_type} lookup failed: {e}")
                records[record_type] = []
        
        return records
```

**Key Changes**:
1. Added safety helper imports
2. Used `configure_logger()` at module level
3. Added `@input_validation()` with `is_valid_domain`
4. Added `@handle_exceptions()` on public method
5. Split internal methods with separate exception handling
6. Added structured logging throughout
7. Improved docstrings and type hints

---

## Testing

### Unit Tests

Create unit tests for migrated modules:

```python
import pytest
from modules.my_module import MyModule

def test_search_valid_input():
    """Test search with valid input"""
    module = MyModule()
    result = module.search("test query")
    assert result["status"] in ["success", "error"]

def test_search_invalid_input():
    """Test search rejects invalid input"""
    module = MyModule()
    with pytest.raises(ValueError):
        module.search("")

def test_search_handles_timeout():
    """Test search handles timeouts gracefully"""
    module = MyModule()
    # Mock timeout scenario
    result = module.search("test query")
    assert "status" in result
```

### Integration Tests

Test with real API calls (use mock servers if needed):

```python
import pytest
from modules.my_module import MyModule

@pytest.mark.integration
def test_search_real_api():
    """Test search with real API"""
    module = MyModule()
    result = module.search("test query")
    assert result["status"] == "success"
    assert "data" in result
```

---

## Rollout Plan

### Phase 1: Foundation (Current)
- ✅ Create safety helpers library
- ✅ Write comprehensive tests
- ✅ Document migration process
- ✅ Create example migrations

### Phase 2: Pilot Modules (Week 1-2)
Priority modules for initial migration:
1. `domain_recon.py` - Frequently used, good test coverage
2. `ip_intel.py` - Well-structured, good example
3. `email_intel.py` - Medium complexity
4. `whois_history.py` - Simple, good starting point

Success criteria:
- All tests pass
- No functional regressions
- Performance unchanged or improved

### Phase 3: Core Modules (Week 3-4)
Core OSINT modules:
1. `passive_dns_enum.py`
2. `certificate_transparency.py`
3. `dns_intelligence.py`
4. `network_analysis.py`
5. `web_discovery.py`

### Phase 4: Specialized Modules (Week 5-6)
Specialized and integration modules:
1. `social_media_footprint.py`
2. `comprehensive_social_passive.py`
3. `search_engine_dorking.py`
4. `paste_site_monitor.py`
5. `darkweb_intel.py`

### Phase 5: Remaining Modules (Week 7-8)
All remaining modules:
- Academic and research modules
- Financial and crypto modules
- Geospatial and IoT modules
- Development and testing modules

### Phase 6: Validation (Week 9)
- Run full test suite
- Performance benchmarking
- Security audit
- Documentation review

---

## Module Priority List

### High Priority (Week 1-2)
Essential modules used frequently:
- [ ] domain_recon.py
- [ ] ip_intel.py
- [ ] email_intel.py
- [ ] whois_history.py
- [ ] passive_dns_enum.py

### Medium Priority (Week 3-4)
Important but less critical:
- [ ] certificate_transparency.py
- [ ] dns_intelligence.py
- [ ] network_analysis.py
- [ ] web_discovery.py
- [ ] web_scraper.py

### Low Priority (Week 5-8)
Specialized or less frequently used:
- [ ] academic_passive.py
- [ ] bitbucket_passive.py
- [ ] code_analysis.py
- [ ] company_intel.py
- [ ] comprehensive_social_passive.py
- [ ] crypto_intel.py
- [ ] darkweb_intel.py
- [ ] digital_forensics.py
- [ ] document_intel.py
- [ ] financial_intel.py
- [ ] flight_intel.py
- [ ] geospatial_intel.py
- [ ] gitlab_passive.py
- [ ] iot_intel.py
- [ ] malware_intel.py
- [ ] passive_search.py
- [ ] paste_site_monitor.py
- [ ] patent_passive.py
- [ ] pattern_matching.py
- [ ] preseeded_databases.py
- [ ] public_breach_search.py
- [ ] rapidapi_osint.py
- [ ] search_engine_dorking.py
- [ ] social_media_footprint.py
- [ ] wayback_machine.py

---

## Common Issues and Solutions

### Issue 1: Circular Import

**Problem**: `from src.passive_osint_common.safety import ...` causes circular import

**Solution**: Use absolute imports or restructure module layout

```python
# Option 1: Absolute import
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.passive_osint_common.safety import safe_request

# Option 2: Restructure to avoid circular dependency
```

### Issue 2: Validator Not Matching Use Case

**Problem**: Built-in validators don't cover your use case

**Solution**: Create custom validator

```python
def is_valid_api_key(value):
    """Custom validator for API keys"""
    return isinstance(value, str) and len(value) == 32 and value.isalnum()

@input_validation(api_key=is_valid_api_key)
def search(self, api_key: str):
    # Function logic
```

### Issue 3: Exception Decorator Masks Error

**Problem**: `@handle_exceptions()` makes debugging harder

**Solution**: Set `reraise=True` during development

```python
# During development
@handle_exceptions(default_return={"status": "error"}, reraise=True)
def search(self, query):
    # Function logic

# In production
@handle_exceptions(default_return={"status": "error"}, reraise=False)
def search(self, query):
    # Function logic
```

---

## Performance Considerations

### Timeout Tuning

Default timeout is 30 seconds. Adjust based on API:

```python
# Fast API - reduce timeout
response = safe_request(url, timeout=10)

# Slow API - increase timeout
response = safe_request(url, timeout=60)

# Very slow API - increase timeout and retries
response = safe_request(url, timeout=120, max_retries=5)
```

### Rate Limiting

Add delays for rate-limited APIs:

```python
# Add 1-second delay between requests
response = safe_request(url, rate_limit_delay=1.0)

# Dynamic delay based on remaining quota
remaining = int(response.headers.get('X-RateLimit-Remaining', 100))
delay = 0.1 if remaining > 50 else 0.5
response = safe_request(url, rate_limit_delay=delay)
```

---

## Questions?

For questions or issues during migration:
1. Check this guide
2. Review example migrations above
3. Check `src/passive_osint_common/safety.py` source
4. Run tests: `pytest tests/test_safety_helpers.py -v`
5. Open an issue with the migration tag

---

**Version**: 1.0  
**Last Updated**: 2025-01-19  
**Phase**: 1 - Foundation Complete, Phase 2 - Migration In Progress
