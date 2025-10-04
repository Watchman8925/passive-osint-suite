# Copilot Instructions for Passive OSINT Suite

## Project Overview

The Passive OSINT Suite is a comprehensive, production-ready Open Source Intelligence (OSINT) gathering platform with enterprise-grade security, anonymity, and operational security features. It's designed for autonomous intelligence collection with a modern web interface, API integration, and advanced analysis capabilities.

## Architecture

### Backend (Python)
- **Framework**: FastAPI for REST API
- **Python Version**: 3.8+ (3.12 recommended)
- **Key Libraries**: 
  - `requests`, `beautifulsoup4` for web scraping
  - `dnspython`, `python-whois` for domain intelligence
  - `cryptography`, `keyring` for security
  - `transformers`, `torch` for ML analysis
  - `neo4j`, `redis`, `elasticsearch` for data storage
  - `slowapi`, `pyjwt` for API security

### Frontend (TypeScript/React)
- **Framework**: React with Vite build tool
- **UI Libraries**: Tailwind CSS, Headless UI, Heroicons
- **State Management**: TanStack Query (React Query)
- **Data Visualization**: Cytoscape, Plotly, Leaflet
- **Type Safety**: TypeScript with strict mode

### Infrastructure
- **Containerization**: Docker and Docker Compose
- **Monitoring**: Prometheus and Grafana
- **Database**: PostgreSQL, Redis, SQLite (optional)
- **CI/CD**: GitHub Actions for linting, security scanning, and Docker builds

## Code Standards

### Python Code
- **Style Guide**: PEP8 compliance enforced by Ruff
- **Line Length**: 88 characters
- **Type Hints**: Use type hints for function parameters and returns
- **Docstrings**: Google-style docstrings for all public functions and classes
- **Async/Await**: Prefer async operations for I/O-bound tasks
- **Error Handling**: Always use proper exception handling; avoid silent failures

```python
# Good example
async def fetch_domain_info(domain: str) -> dict[str, Any]:
    """Fetch comprehensive domain information.
    
    Args:
        domain: The domain name to analyze
        
    Returns:
        Dictionary containing domain intelligence data
        
    Raises:
        ValueError: If domain format is invalid
        RequestError: If network request fails
    """
    try:
        # Implementation
        pass
    except Exception as e:
        logger.error(f"Failed to fetch domain info: {e}")
        raise
```

### TypeScript/React Code
- **Style**: ESLint rules with strict mode
- **Components**: Functional components with hooks
- **Props**: Use TypeScript interfaces for component props
- **State**: Use React Query for server state, local state for UI
- **Naming**: 
  - Components: PascalCase (e.g., `DomainAnalyzer`)
  - Files: kebab-case for utilities, PascalCase for components
  - Hooks: camelCase starting with "use" (e.g., `useInvestigation`)

```typescript
// Good example
interface DomainAnalyzerProps {
  domain: string;
  onComplete?: (results: DomainResults) => void;
}

export function DomainAnalyzer({ domain, onComplete }: DomainAnalyzerProps) {
  const { data, isLoading, error } = useDomainQuery(domain);
  
  if (error) return <ErrorBoundary error={error} />;
  if (isLoading) return <LoadingSpinner />;
  
  return <div>{/* Component JSX */}</div>;
}
```

## Security Requirements

### Critical Security Practices
1. **No Hardcoded Secrets**: All secrets must be in environment variables
2. **Input Validation**: Validate and sanitize all user inputs using Pydantic
3. **Rate Limiting**: Apply rate limits to all API endpoints
4. **Authentication**: Use JWT tokens for API authentication
5. **Data Encryption**: Encrypt sensitive data at rest and in transit
6. **Error Messages**: Never expose sensitive information in error messages

```python
# Always validate inputs
class InvestigationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    targets: List[str] = Field(..., min_items=1, max_items=100)
    
    @classmethod
    def validate_name(cls, v):
        sanitized = re.sub(r'[<>"\\';(){}]', '', v)
        if len(sanitized) != len(v):
            raise ValueError("Invalid characters in name")
        return sanitized.strip()
```

### Environment Variables
Required environment variables must be documented and validated at startup:
- `OSINT_SECRET_KEY`: Secret key for JWT signing (min 32 chars)
- `POSTGRES_PASSWORD`: Database password
- `ENVIRONMENT`: deployment environment (development/production)
- `CORS_ORIGINS`: Allowed CORS origins

## Testing

### Python Tests
- **Framework**: pytest
- **Location**: `tests/` directory
- **Naming**: `test_*.py` for test files, `test_*` for test functions
- **Coverage**: Aim for >80% coverage on critical paths
- **Mocking**: Use `unittest.mock` or `pytest-mock` for external dependencies

```python
# tests/test_domain_analysis.py
import pytest
from modules.domain_analyzer import DomainAnalyzer

def test_domain_validation():
    """Test domain validation logic"""
    analyzer = DomainAnalyzer()
    assert analyzer.validate_domain("example.com") is True
    
    with pytest.raises(ValueError):
        analyzer.validate_domain("invalid domain")
```

### Frontend Tests
- **Framework**: Vitest with React Testing Library
- **Location**: `web/src/**/__tests__/` or `*.test.tsx`
- **Focus**: User interactions and component behavior
- **Coverage**: Critical user flows and error states

```typescript
// components/__tests__/DomainAnalyzer.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import { DomainAnalyzer } from '../DomainAnalyzer';

test('displays domain results', async () => {
  render(<DomainAnalyzer domain="example.com" />);
  await waitFor(() => {
    expect(screen.getByText(/results/i)).toBeInTheDocument();
  });
});
```

## Documentation

### Code Documentation
- **Docstrings**: Required for all public APIs, classes, and complex functions
- **Comments**: Use inline comments for complex logic, not obvious code
- **Type Hints**: Required for all function signatures
- **README Updates**: Update relevant README when adding new features

### API Documentation
- **OpenAPI/Swagger**: Automatically generated from FastAPI
- **Endpoint Descriptions**: Document parameters, responses, and error codes
- **Examples**: Provide request/response examples for complex endpoints

```python
@app.post("/api/investigate", response_model=InvestigationResponse)
async def create_investigation(
    investigation: InvestigationCreate,
    current_user: User = Depends(get_current_user)
) -> InvestigationResponse:
    """Create a new OSINT investigation.
    
    Creates an investigation with specified targets and returns the investigation ID.
    The investigation runs asynchronously and results can be polled.
    
    Args:
        investigation: Investigation configuration with name and targets
        current_user: Authenticated user (injected by dependency)
        
    Returns:
        InvestigationResponse with investigation_id and status
        
    Raises:
        HTTPException(400): Invalid input data
        HTTPException(401): Unauthorized
        HTTPException(429): Rate limit exceeded
    """
    # Implementation
```

## File Organization

### Backend Structure
```
/
├── api/                    # API endpoints and server
├── capabilities/           # Plugin system for OSINT capabilities
├── core/                   # Core business logic
├── database/              # Database models and connections
├── modules/               # OSINT modules (domain, network, etc.)
├── security/              # Security framework (RBAC, monitoring)
├── tests/                 # Test suite
├── config/                # Configuration management
├── utils/                 # Utility functions
└── main.py                # Main entry point
```

### Frontend Structure
```
web/src/
├── components/            # Reusable React components
├── pages/                 # Page-level components
├── hooks/                 # Custom React hooks
├── services/              # API client services
├── types/                 # TypeScript type definitions
├── utils/                 # Utility functions
└── App.tsx               # Root application component
```

## Dependencies

### Adding New Dependencies

#### Python
```bash
# Add to requirements.txt with version
echo "new-package>=1.0.0" >> requirements.txt
pip install -r requirements.txt
```

#### Node.js
```bash
cd web
npm install --save new-package
# or for dev dependencies
npm install --save-dev new-package
```

### Security Considerations
- Always pin major versions in `requirements.txt`
- Run `pip-audit` and `npm audit` for security vulnerabilities
- Check licenses for compatibility
- Update SECURITY_GUIDE.md if adding security-related dependencies

## Development Workflow

### Pre-commit Checks
1. **Linting**: `ruff check .` (Python) or `npm run lint` (Frontend)
2. **Formatting**: `ruff format .` (Python)
3. **Type Checking**: `mypy .` (Python) or `npm run type-check` (Frontend)
4. **Tests**: `pytest tests/` (Python) or `npm test` (Frontend)
5. **Security Audit**: `python scripts/security_audit.py`

### Git Commit Messages
Use conventional commits format:
- `feat: Add domain reputation analysis`
- `fix: Resolve rate limiting issue in API`
- `docs: Update installation guide`
- `refactor: Simplify domain validation logic`
- `test: Add tests for network scanning`
- `security: Fix XSS vulnerability in search`

## Common Patterns

### API Endpoint Pattern
```python
from fastapi import APIRouter, Depends, HTTPException
from slowapi import Limiter
from .dependencies import get_current_user, rate_limit

router = APIRouter()
limiter = Limiter(key_func=lambda: "global")

@router.post("/api/resource")
@limiter.limit("10/minute")
async def create_resource(
    data: ResourceCreate,
    user: User = Depends(get_current_user)
) -> ResourceResponse:
    """Create a new resource."""
    try:
        # Validate input
        validated_data = validate_resource_data(data)
        
        # Perform operation
        result = await resource_service.create(validated_data, user)
        
        # Return response
        return ResourceResponse(
            id=result.id,
            status="success"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Resource creation failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
```

### Async File Operations
```python
import aiofiles

async def read_investigation_file(path: Path) -> dict:
    """Read investigation file asynchronously."""
    async with aiofiles.open(path, mode='r') as f:
        content = await f.read()
        return json.loads(content)
```

### Frontend Data Fetching
```typescript
import { useQuery } from '@tanstack/react-query';
import { investigationApi } from '@/services/api';

export function useInvestigation(id: string) {
  return useQuery({
    queryKey: ['investigation', id],
    queryFn: () => investigationApi.getById(id),
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: 3,
  });
}
```

## Performance Considerations

1. **Async Operations**: Use `async/await` for I/O-bound operations
2. **Database Queries**: Use connection pooling and query optimization
3. **Caching**: Use Redis for frequently accessed data
4. **Rate Limiting**: Implement per-user and global rate limits
5. **Lazy Loading**: Load large datasets progressively
6. **Bundle Size**: Keep frontend bundle size under 1MB

## Troubleshooting

### Common Issues
- **Import Errors**: Check virtual environment activation
- **Docker Issues**: Verify Docker daemon is running
- **API Errors**: Check `.env` file for required variables
- **Frontend Build**: Clear cache with `npm run build -- --force`

### Debugging
- Backend: Use `structlog` for structured logging
- Frontend: Use React DevTools and browser console
- Docker: Use `docker-compose logs -f service-name`

## Related Documentation

- [QUICK_START.md](../QUICK_START.md) - 5-minute setup guide
- [SECURITY_GUIDE.md](../SECURITY_GUIDE.md) - Security best practices
- [SETUP_GUIDE.md](../SETUP_GUIDE.md) - Comprehensive installation guide
- [CODE_REVIEW_SUMMARY.md](../CODE_REVIEW_SUMMARY.md) - Recent code changes
- [README.md](../README.md) - Main project documentation

## Questions or Clarifications?

When uncertain about implementation details:
1. Check existing code patterns in similar modules
2. Review related documentation files
3. Check GitHub issues for similar discussions
4. Follow security-first approach when in doubt
5. Add comments explaining complex logic
6. Write tests to validate behavior

---

**Note**: Always prioritize security, maintainability, and user experience when contributing to this project.
