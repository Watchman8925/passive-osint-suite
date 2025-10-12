# Deployment Fix Documentation

## Problem Statement

The OSINT Suite was experiencing deployment issues where the webpage showed "cannot be displayed" errors. The problems were related to:

1. **Missing Backend Integration**: The `main.py` file didn't have a `--web` flag to start the FastAPI server
2. **Environment Variable Loading**: The `api_server.py` wasn't loading environment variables from `.env` file
3. **Frontend-Backend Communication**: No proxy configuration in Vite for frontend to communicate with backend
4. **Missing Dependencies**: Python and Node.js dependencies weren't documented for installation

## Solution Overview

The fix involved three main components:

### 1. Backend Integration (`main.py`)

**Added `--web` flag** to start the FastAPI server:

```python
parser.add_argument(
    "--web",
    action="store_true",
    help="Start the web API server",
)
```

**Added handler** to start the API server when `--web` flag is used:

```python
if args.web:
    import uvicorn
    from api.api_server import app
    
    console.print("[bold green]🌐 Starting OSINT Suite Web API Server...[/bold green]")
    console.print("Backend API: http://localhost:8000")
    console.print("API Docs: http://localhost:8000/docs")
    console.print("\nPress Ctrl+C to stop the server\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
    return 0
```

### 2. Environment Variable Loading (`api/api_server.py`)

**Added dotenv loading** at the top of the file:

```python
# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional
```

This ensures that `OSINT_SECRET_KEY` and other environment variables are loaded from `.env` file.

### 3. Frontend Proxy Configuration (`web/vite.config.ts`)

**Added proxy configuration** to allow frontend to communicate with backend:

```typescript
server: {
  port: 3000,
  host: true,
  proxy: {
    '/api': {
      target: 'http://localhost:8000',
      changeOrigin: true,
    },
    '/health': {
      target: 'http://localhost:8000',
      changeOrigin: true,
    },
    '/tor': {
      target: 'http://localhost:8000',
      changeOrigin: true,
    },
    '/ws': {
      target: 'ws://localhost:8000',
      ws: true,
    }
  }
}
```

### 4. Environment Configuration

**Created `.env` file** with secure defaults for development:

- Generated secure random `OSINT_SECRET_KEY`
- Set development mode flags
- Added optional service configurations (PostgreSQL, Redis, Elasticsearch)
- Note: `.env` is gitignored to prevent committing secrets

## Quick Start

### Option 1: Using the Full Stack Launcher (Recommended)

```bash
./start_full_stack.sh
```

This script will:
- Check and install dependencies if needed
- Create `.env` file if missing
- Start both backend and frontend
- Display access URLs
- Handle cleanup on Ctrl+C

### Option 2: Manual Start

#### Start Backend Only:
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Create .env file (or copy from .env.example)
python3 -c 'import secrets; print(f"OSINT_SECRET_KEY={secrets.token_urlsafe(32)}")' > .env
# Add other required variables to .env

# Start backend
python3 main.py --web
```

Backend will be available at:
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/api/health

#### Start Frontend (in separate terminal):
```bash
cd web

# Install Node.js dependencies
npm ci

# Start development server
npm run dev
```

Frontend will be available at:
- Web Interface: http://localhost:3000

### Option 3: Using Existing Scripts

You can also use the existing script:
```bash
./start_web_interface.sh
```

But note: This script assumes `.venv` virtual environment exists. You may need to create it first.

## Verification

### 1. Check Backend Health:
```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-12T...",
  "version": "2.0.0",
  "services": {
    "redis": "connected",
    "elasticsearch": "connected",
    "ai_engine": "uninitialized"
  }
}
```

### 2. Check Frontend Proxy:
```bash
curl http://localhost:3000/api/health
```

Should return the same response as above (proxied through frontend).

### 3. Access Web Interface:

Open http://localhost:3000 in your browser. You should see the OSINT Suite web interface.

## Running Tests

### Run Integration Tests:
```bash
pytest tests/test_deployment_integration.py -v
```

This will verify:
- Backend starts with `--web` flag
- API server imports correctly
- Health endpoints are registered
- Environment variables load from `.env`
- Vite proxy configuration exists
- Required dependencies are installed

### Run All Tests:
```bash
pytest tests/ -v
```

Note: Some pre-existing tests may fail due to missing directories or services (PostgreSQL, Neo4j), but the deployment-related tests should pass.

## Troubleshooting

### Backend won't start:

1. **Missing OSINT_SECRET_KEY**:
   ```
   ValueError: OSINT_SECRET_KEY environment variable must be set
   ```
   Solution: Create `.env` file with `OSINT_SECRET_KEY` or run `./start_full_stack.sh`

2. **Module not found errors**:
   ```
   ModuleNotFoundError: No module named 'fastapi'
   ```
   Solution: Install dependencies: `pip3 install -r requirements.txt`

3. **Port already in use**:
   ```
   OSError: [Errno 98] Address already in use
   ```
   Solution: Stop existing process on port 8000 or change port in code

### Frontend won't start:

1. **Dependencies not installed**:
   ```
   Error: Cannot find module 'vite'
   ```
   Solution: Run `cd web && npm ci`

2. **Cannot connect to backend**:
   - Check if backend is running: `curl http://localhost:8000/api/health`
   - Check proxy configuration in `web/vite.config.ts`
   - Check browser console for CORS errors

### Connection Issues:

1. **502 Bad Gateway on `/api/health`**:
   - Backend is not running or not accessible
   - Start backend: `python3 main.py --web`

2. **CORS errors in browser**:
   - Should be resolved by Vite proxy configuration
   - If direct API access needed, backend allows CORS from localhost:3000

## Architecture

```
┌─────────────────┐
│   Web Browser   │
│  (localhost)    │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  Vite Dev Server│  <-- Frontend (React/TypeScript)
│  localhost:3000 │
└────────┬────────┘
         │ Proxy (/api, /health, /tor, /ws)
         ▼
┌─────────────────┐
│  FastAPI Server │  <-- Backend (Python)
│  localhost:8000 │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  OSINT Modules  │  <-- Core Intelligence Gathering
│  (modules/*)    │
└─────────────────┘
```

## Files Modified

1. **main.py**: Added `--web` flag and API server startup logic
2. **api/api_server.py**: Added dotenv loading for environment variables
3. **web/vite.config.ts**: Added proxy configuration for backend communication
4. **tests/test_deployment_integration.py**: New integration tests
5. **tests/test_realtime_feeds.py**: Fixed import path
6. **start_full_stack.sh**: New unified launcher script (recommended)

## Production Deployment

For production deployment, additional steps are required:

1. **Build Frontend**:
   ```bash
   cd web
   npm run build
   ```

2. **Use Production WSGI Server**:
   ```bash
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker api.api_server:app
   ```

3. **Set Production Environment Variables**:
   - Generate secure secrets
   - Set `PRODUCTION=true`
   - Configure real database URLs
   - Set up proper logging

4. **Use Reverse Proxy** (nginx/Apache):
   - Serve frontend build from `web/dist`
   - Proxy API requests to backend

See `DEPLOYMENT.md` for detailed production deployment instructions.

## Additional Resources

- **API Documentation**: http://localhost:8000/docs (when running)
- **Deployment Guide**: `DEPLOYMENT.md`
- **Quick Start**: `QUICK_START.md`
- **Security Guide**: `SECURITY_GUIDE.md`

## Support

If you encounter issues not covered in this document:

1. Check the logs in `logs/` directory
2. Review the API documentation at http://localhost:8000/docs
3. Run tests to identify specific failures: `pytest tests/ -v`
4. Open an issue on GitHub with:
   - Error messages
   - Steps to reproduce
   - System information (OS, Python version, Node.js version)
