# OSINT Suite Documentation

This directory contains comprehensive documentation for the Passive OSINT Suite.

## Contents

### Module Development

- **[MODULE_CAPABILITY_CONTRACT.md](MODULE_CAPABILITY_CONTRACT.md)** - Required interface specification for OSINT modules
  - Standard method definitions
  - Response structure requirements
  - Implementation guidelines
  - Migration guide for existing modules

## Module Interface Standards

All OSINT modules must implement at least one of the following standard methods:

| Method | Purpose | Example Use Cases |
|--------|---------|-------------------|
| `search()` | General search and information gathering | Certificate transparency, breach searches, repository searches |
| `analyze_company()` | Company and business intelligence | Corporate OSINT, supply chain analysis |
| `enumerate()` | Domain/network enumeration | DNS enumeration, subdomain discovery |
| `scrape()` | Web scraping and content extraction | Website analysis, data harvesting |
| `fetch_snapshots()` | Historical data retrieval | Wayback Machine, timeline reconstruction |
| `get_history()` | Historical records | WHOIS history, registration changes |
| `scrape_profiles()` | Social media profile discovery | Social OSINT, presence mapping |
| `dork()` | Search engine dorking | Google dorking, advanced queries |

All methods must return a dictionary with:
- `status`: "success" or "error"
- `data`: Result data (when status is "success")
- `error`: Error message (when status is "error")

## Testing

Module contract compliance is verified by:
- `tests/test_module_contracts.py` - Comprehensive test suite

Run tests with:
```bash
pytest tests/test_module_contracts.py -v
```

## Module Adapters

Modules that have existing functionality but don't use standard method names are automatically adapted at runtime using the `modules/module_adapters.py` system. This provides thin wrapper methods that delegate to the module's primary functionality while conforming to the standard interface.

## Adding New Modules

1. Create your module class inheriting from `OSINTUtils`
2. Implement at least one standard interface method
3. Add your module to `MODULE_REGISTRY` in `modules/__init__.py`
4. Specify the module category
5. Write tests to verify the interface
6. Document any special requirements or API keys needed

Example:
```python
from utils.osint_utils import OSINTUtils

class MyNewModule(OSINTUtils):
    def __init__(self):
        super().__init__()
    
    def search(self, target, **kwargs):
        """Standard search interface"""
        try:
            # Your implementation here
            result = self.do_investigation(target)
            return {"status": "success", "data": result}
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return {"status": "error", "error": str(e)}
```

## Best Practices

1. **Error Handling**: Always wrap functionality in try/except and return structured errors
2. **Logging**: Use `self.logger` for consistent logging
3. **API Keys**: Use `self.get_api_key()` to retrieve API keys securely
4. **Rate Limiting**: Respect rate limits and use exponential backoff
5. **OPSEC**: Follow operational security best practices for passive intelligence gathering
6. **Documentation**: Document all methods with clear docstrings

## Module Categories

Modules are organized into the following categories:

- **domain** - Domain and DNS intelligence
- **network** - Network and IP analysis
- **web** - Web scraping and discovery
- **social** - Social media intelligence
- **breach** - Data breach searches
- **business** - Company and business intelligence
- **email** - Email intelligence
- **code** - Code repository analysis
- **forensics** - Digital forensics
- **crypto** - Cryptocurrency intelligence
- **aviation** - Flight and aircraft intelligence
- **geospatial** - Location intelligence
- **financial** - Financial intelligence
- **document** - Document leak monitoring
- **darkweb** - Dark web intelligence
- **iot** - IoT device intelligence
- **malware** - Malware and threat intelligence
- **analysis** - Intelligence analysis tools
- **investigation** - Investigation frameworks

## API Integration

The API server at `/api/modules/execute` automatically detects and calls the appropriate standard method for each module. Modules are tried in priority order:

1. `search`
2. `analyze_company`
3. `enumerate`
4. `scrape`
5. `fetch_snapshots`
6. `get_history`
7. `scrape_profiles`
8. `dork`

## Support

For issues or questions:
- Check the module contract documentation
- Review existing module implementations
- Run the test suite to verify compliance
- Consult the main project README
