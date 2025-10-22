# Module Execution Integration

This document describes the integration of module execution with the FastAPI backend's `/api/modules/execute` endpoint.

## Overview

The frontend now properly integrates with the backend's dynamic module execution system. All module actions trigger real API calls rather than simulated loading states.

## Changes Made

### 1. Dashboard Module Actions (`web/src/ModernApp.tsx`)

**Before:**
```typescript
const handleModuleRun = async (moduleId) => {
  setIsLoading(true);
  setSelectedModule(moduleId);
  // Simulate API call
  setTimeout(() => {
    setIsLoading(false);
    setSelectedModule(null);
  }, 2000);
};
```

**After:**
```typescript
const handleModuleRun = async (moduleId) => {
  setIsLoading(true);
  setSelectedModule(moduleId);
  
  try {
    const moduleName = moduleNameMap[moduleId] || moduleId;
    const response = await fetch(`${API_URL}/api/modules/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken || ''}`
      },
      body: JSON.stringify({
        module_name: moduleName,
        parameters: {}
      }),
    });
    
    if (!response.ok) {
      throw new Error('Module execution failed');
    }
    
    const data = await response.json();
    // Handle results...
  } catch (err) {
    // Display error to user
  } finally {
    setIsLoading(false);
  }
};
```

### 2. Domain Investigation Modal (`web/src/components/modules/DomainInvestigationModal.tsx`)

**Before:**
- Posted to legacy endpoint: `/api/modules/domain/run`
- Used custom request format

**After:**
- Posts to standardized endpoint: `/api/modules/execute`
- Uses `ModuleExecutionRequest` contract:
  ```json
  {
    "module_name": "domain_recon",
    "parameters": {
      "target": "example.com",
      "dns_lookup": true,
      "whois_lookup": true,
      "subdomain_scan": true
    }
  }
  ```
- Handles `ModuleExecutionResponse` format:
  ```json
  {
    "status": "success|error",
    "module_name": "domain_recon",
    "result": {...},
    "error": "...",
    "execution_time": 1.5
  }
  ```

### 3. NLP Assistant (`web/src/components/chat/ChatInterface.tsx`)

**Status:** Already properly integrated ✅

The chat interface already correctly uses:
- `/api/nlp/parse` for parsing natural language commands
- `/api/nlp/execute` for executing parsed commands
- Proper error handling with toast notifications
- Clear result presentation

## API Endpoint

### POST `/api/modules/execute`

**Request:**
```json
{
  "module_name": "string",
  "parameters": {
    "key": "value"
  }
}
```

**Response:**
```json
{
  "status": "success|error",
  "module_name": "string",
  "result": {},
  "error": "string",
  "execution_time": 1.5
}
```

## Module Name Mapping

Frontend module IDs are mapped to backend module names:

| Frontend ID | Backend Module Name |
|-------------|---------------------|
| `domain` | `domain_recon` |
| `email` | `email_intel` |
| `social_passive` | `social_media_footprint` |
| `ip` | `ip_intel` |
| `company` | `company_intel` |
| `crypto` | `crypto_intel` |
| `flight` | `flight_intel` |
| And more... | See ModernApp.tsx |

## Error Handling

All module execution errors are:
1. Caught and logged to the console
2. Displayed to the user via alerts or toast notifications
3. Not silently swallowed

Example error flow:
```typescript
try {
  const response = await fetch('/api/modules/execute', {...});
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail);
  }
  // Success handling
} catch (err) {
  toast.error(err.message); // Show to user
  console.error('Module execution error:', err); // Log for debugging
}
```

## Testing

Comprehensive tests have been added for the DomainInvestigationModal:
- Verifies correct API endpoint usage
- Tests ModuleExecutionResponse handling
- Tests error handling and user notifications
- Tests input validation

Run tests with:
```bash
cd web
npm test
```

## Security

- CodeQL security scan: **0 alerts** ✅
- All user inputs are validated
- Authorization headers included for authenticated requests
- No sensitive data logged to console

## Next Steps

1. Consider adding a results modal/panel to display module execution results instead of alerts
2. Add progress indicators for long-running modules
3. Consider adding module execution history/logs
4. Add ability to cancel running modules

## References

- Backend API: `/api/api_server.py` (lines 1483-1600)
- Module Registry: `/modules/__init__.py`
- Frontend Implementation: `/web/src/ModernApp.tsx` and `/web/src/components/modules/DomainInvestigationModal.tsx`
