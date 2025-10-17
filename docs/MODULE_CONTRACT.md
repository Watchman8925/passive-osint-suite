# OSINT Module Contract

## Overview
All OSINT modules in the `modules/` directory inherit from `OSINTUtils` and must implement at least one primary execution method. This document defines the expected interface and behavior for OSINT modules.

## Module Structure

### Base Class
All modules inherit from `utils.osint_utils.OSINTUtils`, which provides:
- Logging capabilities (`self.logger`)
- Input validation methods (`validate_input`)
- Security utilities (Tor/VPN integration, rate limiting)
- Common HTTP request handling
- Error handling patterns

### Module Registry
Modules are registered in `modules/__init__.py` in the `MODULE_REGISTRY` dictionary with:
- `class`: The module class reference
- `description`: Human-readable description of the module's purpose
- `category`: Category for organization (domain, network, social, business, etc.)

## Required Methods

### Primary Execution Methods
Every module must implement **at least one** of the following primary methods:

#### 1. `search(query: str, **kwargs) -> Dict[str, Any]`
General-purpose search method for modules that perform searches across multiple sources.

**Returns:**
```python
{
    "status": "success" | "error",
    "data": { ... },  # If success
    "error": "Error message"  # If error
}
```

#### 2. `analyze_*(**kwargs) -> Dict[str, Any]`
Domain-specific analysis methods:
- `analyze_domain(domain: str)` - Domain analysis
- `analyze_company(company_name: str, domain: Optional[str])` - Company intelligence
- `analyze_email(email: str)` - Email intelligence
- `analyze_crypto_address(address: str, currency_type: str)` - Cryptocurrency analysis

**Returns:** Same format as `search()`

#### 3. `enumerate(**kwargs) -> Dict[str, Any]`
For modules that enumerate resources (subdomains, DNS records, etc.).

#### 4. `scrape(**kwargs) -> Dict[str, Any]`
For web scraping modules that extract data from websites.

#### 5. `fetch_snapshots(**kwargs) -> Dict[str, Any]`
For modules that retrieve historical data (Wayback Machine, etc.).

#### 6. `get_history(**kwargs) -> Dict[str, Any]`
For modules that provide historical intelligence data.

#### 7. `scrape_profiles(**kwargs) -> Dict[str, Any]`
For social media and profile scraping modules.

#### 8. `dork(**kwargs) -> Dict[str, Any]`
For search engine dorking modules.

## Response Format

### Success Response
```python
{
    "status": "success",
    "data": {
        # Module-specific data structure
        # Should include timestamp, target, and results
    },
    "timestamp": "ISO-8601 timestamp",  # Optional
    "execution_time": 1.23  # Optional, in seconds
}
```

### Error Response
```python
{
    "status": "error",
    "error": "Human-readable error message",
    "error_type": "ValidationError | APIError | NetworkError | ...",  # Optional
    "target": "target identifier",  # Optional
}
```

## Error Handling

### Input Validation
Modules should validate inputs using `self.validate_input(value, type)`:
```python
if not self.validate_input(domain, "domain"):
    return {"status": "error", "error": f"Invalid domain format: {domain}"}
```

### Exception Handling
Modules should catch and handle exceptions gracefully:
```python
try:
    # Module logic
    return {"status": "success", "data": result}
except APIError as e:
    self.logger.error(f"API error: {e}")
    return {"status": "error", "error": f"API error: {str(e)}"}
except Exception as e:
    self.logger.error(f"Unexpected error: {e}")
    return {"status": "error", "error": f"Internal error: {str(e)}"}
```

### Logging
All modules should log:
- Start of operations: `self.logger.info(f"Starting analysis for: {target}")`
- Errors: `self.logger.error(f"Operation failed: {error}")`
- Warnings: `self.logger.warning(f"Warning message")`
- Debug info: `self.logger.debug(f"Debug details")`

## API Integration

### API Execution Endpoint
The API server (`api/api_server.py`) calls modules via the `/api/execute` endpoint:

```python
# The server checks for methods in priority order:
execution_methods = [
    "search",
    "analyze_company",
    "analyze_domain",
    "analyze_email",
    "analyze_crypto_address",
    "enumerate",
    "scrape",
    "fetch_snapshots",
    "get_history",
    "scrape_profiles",
    "dork",
]

# Try specific execution methods first
for method_name in execution_methods:
    if hasattr(module_instance, method_name):
        result = getattr(module_instance, method_name)(**request.parameters)
        break

# If no specific method found, try pattern-based methods
# Looks for methods starting with: analyze_, search_, scan_, track_, monitor_, comprehensive_
```

## Module Categories

Modules are organized into categories for discovery:

- **domain**: Domain and DNS intelligence (`domain_recon`, `whois_history`, etc.)
- **network**: Network and IP intelligence (`ip_intel`, `network_analysis`, etc.)
- **web**: Web scraping and discovery (`web_scraper`, `wayback_machine`, etc.)
- **social**: Social media intelligence (`social_media_footprint`, etc.)
- **breach**: Data breach and leak monitoring (`public_breach_search`, etc.)
- **business**: Business intelligence (`company_intel`)
- **email**: Email intelligence (`email_intel`)
- **crypto**: Cryptocurrency intelligence (`crypto_intel`)
- **code**: Code repository intelligence (`github_search`, `code_analysis`, etc.)
- **forensics**: Digital forensics (`digital_forensics`, `metadata_extractor`)
- **analysis**: Advanced analysis engines (`conspiracy_analyzer`, etc.)

## Testing

### Module Interface Tests
All modules should be tested for:
1. Presence of at least one execution method
2. Proper response format (success/error)
3. Input validation
4. Error handling

Example test:
```python
def test_module_interface():
    module = DomainRecon()
    
    # Test that module has at least one execution method
    assert hasattr(module, 'analyze_domain')
    
    # Test error response for invalid input
    result = module.analyze_domain("")
    assert result["status"] == "error"
    
    # Test success response format
    result = module.analyze_domain("example.com")
    assert "status" in result
    assert result["status"] in ["success", "error"]
```

## Best Practices

1. **Fail Gracefully**: Never raise unhandled exceptions; return error responses
2. **Validate Input**: Always validate user input before processing
3. **Log Appropriately**: Use appropriate log levels (info, warning, error, debug)
4. **Document Methods**: Include docstrings for all public methods
5. **Return Consistent Format**: Always return dict with "status" key
6. **Handle API Failures**: Account for rate limits, timeouts, and API errors
7. **Respect Privacy**: Follow OPSEC best practices; use Tor when configured
8. **Be Defensive**: Handle missing API keys, network errors, and malformed data

## Adding New Modules

When adding a new module:

1. Create the module file in `modules/`
2. Inherit from `OSINTUtils`
3. Implement at least one primary execution method
4. Add to `MODULE_REGISTRY` in `modules/__init__.py`
5. Add to appropriate `CATEGORIES` dict
6. Write tests for the module interface
7. Update documentation

Example:
```python
# modules/my_new_module.py
from utils.osint_utils import OSINTUtils

class MyNewModule(OSINTUtils):
    def __init__(self):
        super().__init__()
    
    def search(self, query: str, **kwargs):
        """Search for information."""
        if not self.validate_input(query, "domain"):
            return {"status": "error", "error": "Invalid query"}
        
        try:
            # Module logic here
            return {"status": "success", "data": {"results": []}}
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return {"status": "error", "error": str(e)}
```

Then register it:
```python
# modules/__init__.py
from .my_new_module import MyNewModule

MODULE_REGISTRY["my_new_module"] = {
    "class": MyNewModule,
    "description": "My new OSINT module",
    "category": "general",
}
```

## Validation

To validate all modules comply with the contract, run:
```bash
python -m pytest tests/test_module_contracts.py
```

This will check that:
- All modules in MODULE_REGISTRY exist and can be instantiated
- All modules have at least one execution method
- All execution methods return proper response format
- Error handling works correctly
