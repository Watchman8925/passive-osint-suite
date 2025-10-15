# OSINT Module Capability Contract

## Overview

All OSINT modules in the Passive OSINT Suite must implement at least one of the standard capability methods defined in this contract. This ensures consistent integration with the API server's module execution endpoint (`/api/modules/execute`).

## Standard Capability Methods

Modules should implement **at least one** of the following methods, depending on their primary function:

### 1. `search(target, **kwargs) -> Dict[str, Any]`

**Purpose**: General search and information gathering.

**Use Cases**:
- Certificate transparency lookups
- Public breach searches
- GitHub repository searches
- Any general search functionality

**Parameters**:
- `target` (str): The target to search for (domain, email, username, etc.)
- `**kwargs`: Additional search parameters (filters, limits, etc.)

**Returns**: Dictionary with keys:
- `status` (str): "success" or "error"
- `data` (Any): Search results (when status is "success")
- `error` (str): Error message (when status is "error")

**Example**:
```python
def search(self, target, limit=10):
    """Search for repositories, profiles, or data related to target"""
    return {
        "status": "success",
        "data": {
            "query": target,
            "results": [...],
            "total": 42
        }
    }
```

### 2. `analyze_company(company_name, domain=None, **kwargs) -> Dict[str, Any]`

**Purpose**: Company and business intelligence analysis.

**Use Cases**:
- Corporate OSINT
- Business entity investigations
- Supply chain analysis

**Parameters**:
- `company_name` (str): Name of the company
- `domain` (str, optional): Company domain for enhanced analysis
- `**kwargs`: Additional analysis parameters

**Returns**: Dictionary with company intelligence data including:
- Basic company information
- Domain analysis
- Social media presence
- Employee information
- Financial data
- Technology stack

**Example**:
```python
def analyze_company(self, company_name, domain=None):
    """Comprehensive company intelligence gathering"""
    return {
        "company_name": company_name,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "company_info": {...},
        "domain_analysis": {...},
        "employees": {...}
    }
```

### 3. `enumerate(target, **kwargs) -> Dict[str, Any]`

**Purpose**: Domain, subdomain, or network enumeration.

**Use Cases**:
- DNS enumeration
- Subdomain discovery
- Network mapping
- Certificate transparency enumeration

**Parameters**:
- `target` (str): Domain or network target to enumerate
- `**kwargs`: Enumeration options (depth, methods, etc.)

**Returns**: Dictionary with enumeration results:
- `status` (str): "success" or "error"
- `data` (Dict): Enumerated items (subdomains, DNS records, etc.)

**Example**:
```python
def enumerate(self, target):
    """Enumerate subdomains and DNS records for target"""
    return {
        "status": "success",
        "data": {
            "target": target,
            "subdomains": [...],
            "dns_records": {...}
        }
    }
```

### 4. `scrape(target, keywords=None, **kwargs) -> Dict[str, Any]`

**Purpose**: Web scraping and content extraction.

**Use Cases**:
- Website content analysis
- Keyword extraction
- Data harvesting from web pages

**Parameters**:
- `target` (str): URL or domain to scrape
- `keywords` (List[str], optional): Keywords to search for
- `**kwargs`: Scraping options (depth, timeout, etc.)

**Returns**: Dictionary with scraped content:
- `status` (str): "success" or "error"
- `data` (Dict): Extracted content, links, metadata

**Example**:
```python
def scrape(self, target, keywords=None):
    """Scrape website for content and keywords"""
    return {
        "status": "success",
        "data": {
            "url": target,
            "content": "...",
            "keywords_found": [...],
            "links": [...]
        }
    }
```

### 5. `fetch_snapshots(url, **kwargs) -> Dict[str, Any]`

**Purpose**: Retrieve historical snapshots or archived data.

**Use Cases**:
- Wayback Machine queries
- Historical website versions
- Timeline reconstruction

**Parameters**:
- `url` (str): URL to fetch historical data for
- `**kwargs`: Options (date range, limit, etc.)

**Returns**: Dictionary with historical snapshots:
- `status` (str): "success" or "error"
- `data` (Dict): List of snapshots with timestamps and URLs

**Example**:
```python
def fetch_snapshots(self, url, limit=10):
    """Fetch historical snapshots from archive"""
    return {
        "status": "success",
        "data": {
            "url": url,
            "snapshots": [
                {"timestamp": "2023-01-01", "archive_url": "..."},
                ...
            ]
        }
    }
```

### 6. `get_history(target, **kwargs) -> Dict[str, Any]`

**Purpose**: Retrieve historical records and registration data.

**Use Cases**:
- WHOIS history
- Domain registration changes
- Historical ownership data

**Parameters**:
- `target` (str): Domain or entity to get history for
- `**kwargs`: History query options

**Returns**: Dictionary with historical data:
- `status` (str): "success" or "error"
- `data` (Dict): Historical records with timestamps

**Example**:
```python
def get_history(self, target):
    """Get WHOIS and registration history"""
    return {
        "status": "success",
        "data": {
            "domain": target,
            "history": [
                {"date": "2020-01-01", "registrar": "...", "owner": "..."},
                ...
            ]
        }
    }
```

### 7. `scrape_profiles(name_or_handle, **kwargs) -> Dict[str, Any]`

**Purpose**: Social media profile discovery and analysis.

**Use Cases**:
- Social media OSINT
- Online presence mapping
- Profile aggregation

**Parameters**:
- `name_or_handle` (str): Name or username to search for
- `**kwargs`: Platform filters, search options

**Returns**: Dictionary with discovered profiles:
- `status` (str): "success" or "error"
- `data` (Dict): Found profiles across platforms

**Example**:
```python
def scrape_profiles(self, name_or_handle):
    """Find social media profiles across platforms"""
    return {
        "status": "success",
        "data": {
            "query": name_or_handle,
            "profiles": {
                "twitter": {...},
                "linkedin": {...},
                "github": {...}
            }
        }
    }
```

### 8. `dork(query, engines=None, **kwargs) -> Dict[str, Any]`

**Purpose**: Search engine dorking and advanced queries.

**Use Cases**:
- Google dorking
- Bing advanced searches
- DuckDuckGo queries
- Specialized search operators

**Parameters**:
- `query` (str): Dork query with operators
- `engines` (List[str], optional): Search engines to use
- `**kwargs**: Additional options (limit, safe mode, etc.)

**Returns**: Dictionary with search results:
- `status` (str): "success" or "error"
- `data` (Dict): Results by search engine

**Example**:
```python
def dork(self, query, engines=None):
    """Execute search engine dork queries"""
    return {
        "status": "success",
        "data": {
            "query": query,
            "engines_used": engines or ["duckduckgo"],
            "results": [...]
        }
    }
```

## Implementation Guidelines

### For Existing Modules

If your module already has a primary method but not one of the standard names, add a thin wrapper:

```python
class MyModule(OSINTUtils):
    def analyze_target(self, target):
        """Main analysis method"""
        # Existing implementation
        pass
    
    # Add standard interface wrapper
    def search(self, target, **kwargs):
        """Standard search interface - delegates to analyze_target"""
        return self.analyze_target(target)
```

### For New Modules

New modules should implement at least one standard method directly:

```python
class NewModule(OSINTUtils):
    def __init__(self):
        super().__init__()
    
    def search(self, target, **kwargs):
        """Implement standard search method"""
        # Implementation here
        return {"status": "success", "data": {...}}
```

### Error Handling

All methods must handle errors gracefully and return structured error information:

```python
def search(self, target, **kwargs):
    try:
        # Implementation
        return {"status": "success", "data": result}
    except Exception as e:
        self.logger.error(f"Search failed: {e}")
        return {"status": "error", "error": str(e)}
```

### Response Structure

All methods must return a dictionary with at least:
- `status` key with value "success" or "error"
- `data` key (when status is "success") or `error` key (when status is "error")

## Module Categories and Recommended Methods

| Category | Recommended Methods |
|----------|-------------------|
| domain | `enumerate`, `search` |
| network | `enumerate`, `search` |
| web | `scrape`, `search` |
| social | `scrape_profiles`, `search` |
| breach | `search` |
| business | `analyze_company` |
| email | `search` |
| code | `search` |
| forensics | `search` |
| aviation | `search` |
| crypto | `search` |

## Testing Requirements

All modules must have tests that verify:
1. At least one standard method is implemented
2. The method returns the correct response structure
3. Error cases return proper error responses
4. The method is callable from the API endpoint

See `tests/test_module_contracts.py` for examples.

## API Integration

The `/api/modules/execute` endpoint (in `api/api_server.py`) automatically detects and calls the appropriate method based on what's available in the module. Modules are tried in this order:

1. `search`
2. `analyze_company`
3. `enumerate`
4. `scrape`
5. `fetch_snapshots`
6. `get_history`
7. `scrape_profiles`
8. `dork`

If none of these methods are found, a 400 error is returned.

## Migration Guide

To update an existing module:

1. Identify your module's primary functionality
2. Choose the most appropriate standard method name
3. Either rename your main method OR add a wrapper method
4. Ensure proper return structure (dict with status/data/error)
5. Add error handling if not present
6. Update module tests to verify the standard interface

Example migration:

```python
# Before
class MyModule(OSINTUtils):
    def investigate(self, target):
        return some_result

# After
class MyModule(OSINTUtils):
    def investigate(self, target):
        """Internal method - kept for backwards compatibility"""
        return some_result
    
    def search(self, target, **kwargs):
        """Standard interface"""
        result = self.investigate(target)
        return {"status": "success", "data": result}
```
