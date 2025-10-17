# Error Handling Guide

## Overview
This document describes the error handling conventions and patterns used throughout the OSINT Suite, covering both backend (Python/FastAPI) and frontend (React/TypeScript) components.

## Backend Error Handling

### Module Error Responses
All OSINT modules return standardized error responses:

```python
{
    "status": "error",
    "error": "Human-readable error message",
    "error_type": "ValidationError | APIError | NetworkError | ...",  # Optional
    "target": "target identifier",  # Optional
}
```

### API Error Responses
The FastAPI server returns HTTP error responses with JSON bodies:

```python
{
    "detail": "Error message",
    "error_type": "specific_error_type",  # When applicable
}
```

#### HTTP Status Codes
- **200 OK**: Successful operation
- **400 Bad Request**: Invalid input, validation errors
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found (investigation, module, etc.)
- **422 Unprocessable Entity**: Pydantic validation errors
- **500 Internal Server Error**: Unexpected server errors
- **503 Service Unavailable**: Service temporarily unavailable

### Exception Handling in Modules

#### Input Validation
```python
from utils.osint_utils import OSINTUtils

class MyModule(OSINTUtils):
    def analyze_target(self, target: str):
        # Validate input
        if not self.validate_input(target, "domain"):
            return {
                "status": "error",
                "error": f"Invalid domain format: {target}"
            }
        
        try:
            # Module logic
            return {"status": "success", "data": result}
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"status": "error", "error": str(e)}
```

#### Exception Categories
```python
# API Errors - External service failures
try:
    response = requests.get(api_url)
    response.raise_for_status()
except requests.HTTPError as e:
    return {"status": "error", "error": f"API error: {e}"}

# Network Errors - Connection issues
except requests.ConnectionError as e:
    return {"status": "error", "error": f"Network error: {e}"}

# Timeout Errors
except requests.Timeout as e:
    return {"status": "error", "error": f"Request timeout: {e}"}

# Generic catch-all
except Exception as e:
    self.logger.exception("Unexpected error")
    return {"status": "error", "error": f"Internal error: {str(e)}"}
```

#### Logging Best Practices
```python
# Info level - normal operations
self.logger.info(f"Starting analysis for: {target}")

# Warning level - recoverable issues
self.logger.warning(f"API rate limit reached, using fallback")

# Error level - operation failures
self.logger.error(f"Failed to analyze target: {e}")

# Debug level - detailed troubleshooting
self.logger.debug(f"Response data: {response_data}")

# Exception level - unexpected errors with full traceback
self.logger.exception("Unexpected error during analysis")
```

### API Endpoint Error Handling

#### FastAPI HTTPException
```python
from fastapi import HTTPException

# 404 Not Found
if module_name not in MODULE_REGISTRY:
    raise HTTPException(
        status_code=404,
        detail=f"Module '{module_name}' not found"
    )

# 400 Bad Request
if not hasattr(module_instance, "search"):
    raise HTTPException(
        status_code=400,
        detail=f"Module does not support search operation"
    )

# 401 Unauthorized
if not user_authenticated:
    raise HTTPException(
        status_code=401,
        detail="Authentication required"
    )
```

#### Audit Trail Integration
```python
try:
    # Operation logic
    result = perform_operation()
    
    # Log successful operation
    audit_trail.log_operation(
        operation="module_execute",
        actor=user_id,
        target=target,
        metadata={"result": "success"}
    )
except Exception as e:
    # Log error
    audit_trail.log_operation(
        operation="module_execute_error",
        actor=user_id,
        target=target,
        metadata={"error": str(e)}
    )
    raise
```

## Frontend Error Handling

### API Client Error Interceptor
The frontend uses Axios interceptors for centralized error handling:

```typescript
// services/osintAPI.ts
this.client.interceptors.response.use(
  (response) => {
    finishProgress();
    return response;
  },
  (error) => {
    finishProgress();
    
    if (error.response?.status === 401) {
      toast.error('Authentication required');
      localStorage.removeItem('osint_auth_token');
    } else if (error.response?.status === 403) {
      toast.error('Access denied');
    } else if (error.response?.status >= 500) {
      toast.error('Server error - please try again');
    } else if (error.code === 'ECONNABORTED') {
      toast.error('Request timeout');
    } else {
      toast.error(`Error: ${error.response?.data?.detail || error.message}`);
    }
    
    return Promise.reject(error);
  }
);
```

### Component-Level Error Handling

#### Try-Catch with Toast Notifications
```typescript
import toast from 'react-hot-toast';

async function executeModule(moduleName: string, params: any) {
  try {
    const result = await osintAPI.executeModule(moduleName, params);
    toast.success('Module executed successfully');
    return result;
  } catch (error) {
    // Error already handled by interceptor, but we can add specific handling
    console.error('Module execution failed:', error);
    // The interceptor already shows a toast, so we don't duplicate
    throw error;
  }
}
```

#### React Error Boundaries
```typescript
// components/ErrorBoundary.tsx
class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };
  
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  
  componentDidCatch(error: Error, errorInfo: any) {
    console.error('Error caught by boundary:', error, errorInfo);
  }
  
  render() {
    if (this.state.hasError) {
      return (
        <div className="error-container">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message}</p>
          <button onClick={() => window.location.reload()}>
            Reload Page
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
```

#### Form Validation
```typescript
// Validate inputs before API call
function validateModuleInput(moduleName: string, params: any): string | null {
  if (moduleName === 'domain_recon' && !params.domain) {
    return 'Domain is required';
  }
  
  if (params.domain && !isValidDomain(params.domain)) {
    return 'Invalid domain format';
  }
  
  return null;
}

// In component
const handleSubmit = async () => {
  const validationError = validateModuleInput(moduleName, params);
  if (validationError) {
    toast.error(validationError);
    return;
  }
  
  try {
    await executeModule(moduleName, params);
  } catch (error) {
    // Already handled by interceptor
  }
};
```

### Loading and Error States

#### UI State Management
```typescript
interface ModuleState {
  loading: boolean;
  error: string | null;
  data: any | null;
}

function ModuleExecutor() {
  const [state, setState] = useState<ModuleState>({
    loading: false,
    error: null,
    data: null
  });
  
  const executeModule = async () => {
    setState({ loading: true, error: null, data: null });
    
    try {
      const result = await osintAPI.executeModule(moduleName, params);
      setState({ loading: false, error: null, data: result });
    } catch (error) {
      setState({ 
        loading: false, 
        error: error.message, 
        data: null 
      });
    }
  };
  
  return (
    <div>
      {state.loading && <Spinner />}
      {state.error && <Alert type="error">{state.error}</Alert>}
      {state.data && <Results data={state.data} />}
    </div>
  );
}
```

## Error Recovery Patterns

### Retry Logic
```python
import time
from typing import Optional

def retry_with_backoff(
    func,
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0
) -> Optional[any]:
    """Retry a function with exponential backoff."""
    for attempt in range(max_attempts):
        try:
            return func()
        except Exception as e:
            if attempt == max_attempts - 1:
                raise
            
            delay = initial_delay * (backoff_factor ** attempt)
            logging.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s")
            time.sleep(delay)
```

### Fallback Mechanisms
```python
def get_data_with_fallback(primary_source, fallback_source):
    """Try primary source, fall back to secondary."""
    try:
        return primary_source.fetch()
    except Exception as e:
        logging.warning(f"Primary source failed: {e}. Using fallback")
        try:
            return fallback_source.fetch()
        except Exception as e2:
            logging.error(f"Fallback also failed: {e2}")
            return {"status": "error", "error": "All sources failed"}
```

### Circuit Breaker Pattern
```python
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open
    
    def call(self, func):
        if self.state == "open":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "half_open"
            else:
                raise Exception("Circuit breaker is open")
        
        try:
            result = func()
            if self.state == "half_open":
                self.state = "closed"
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
            raise
```

## Testing Error Handling

### Backend Tests
```python
def test_module_error_handling():
    module = DomainRecon()
    
    # Test invalid input
    result = module.analyze_domain("")
    assert result["status"] == "error"
    assert "error" in result
    
    # Test malformed input
    result = module.analyze_domain("not-a-valid-domain!@#")
    assert result["status"] == "error"
```

### Frontend Tests
```typescript
describe('Module Execution Error Handling', () => {
  it('should show error toast on API failure', async () => {
    const mockError = { response: { status: 500, data: { detail: 'Server error' }}};
    jest.spyOn(api, 'executeModule').mockRejectedValue(mockError);
    
    render(<ModuleExecutor />);
    fireEvent.click(screen.getByText('Execute'));
    
    await waitFor(() => {
      expect(screen.getByText(/Server error/i)).toBeInTheDocument();
    });
  });
});
```

## Monitoring and Alerting

### Error Logging
- All errors are logged with appropriate severity levels
- Audit trail captures all operations and errors
- Logs include context (user, target, parameters)

### Health Checks
```python
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "services": {
            "database": "connected",
            "redis": "connected"
        }
    }
```

## Best Practices Summary

1. **Always validate input** before processing
2. **Return structured error responses** with clear messages
3. **Log errors appropriately** with sufficient context
4. **Use appropriate HTTP status codes** in APIs
5. **Handle errors at the right level** (module, API, UI)
6. **Provide actionable error messages** to users
7. **Implement retry logic** for transient failures
8. **Use fallback mechanisms** when available
9. **Test error paths** as thoroughly as success paths
10. **Monitor and alert** on error patterns
