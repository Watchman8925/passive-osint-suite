#!/usr/bin/env python3
"""
Advanced OSINT Suite API Server
FastAPI-based backend with AI integration, real-time WebSocket support,
and comprehensive investigation management.
"""

import asyncio
import logging
import os
import importlib
import importlib.util
from contextlib import asynccontextmanager

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass  # dotenv is optional
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Literal, TYPE_CHECKING, cast, Tuple
import time

# Core OSINT modules and dependencies
from security.audit_trail import audit_trail
from capabilities import REGISTRY as CAPABILITY_REGISTRY
from execution.engine import ExecutionEngine, compute_investigation_provenance
from investigations.investigation_adapter import PersistentInvestigationStore
from security.opsec_policy import enforce_policy
from planner import Planner
from utils.transport import get_tor_status

# Minimal pydantic BaseModel/Field import
from pydantic import BaseModel, Field  # type: ignore

try:
    from investigations.investigation_manager import InvestigationManager  # type: ignore
except Exception:  # pragma: no cover - optional advanced manager
    InvestigationManager = None
from database.graph_database import GraphDatabaseAdapter

# OSINT Module Registry
from modules import (
    CATEGORIES,
    MODULE_REGISTRY,
    get_module,
    get_modules_by_category,
)
from realtime.realtime_feeds import RealTimeIntelligenceFeed
from reporting.report_scheduler import ReportScheduler
from reporting.reporting_engine import EnhancedReportingEngine
from security.data_access_control import data_access_control

# Security Framework Integration
from security.rbac_manager import rbac_manager
from security.security_api import (
    security_controller,
    setup_security_routes,
)
from security.security_monitor import security_monitor

# Use imported items to avoid unused import warnings
_ = (
    CATEGORIES,
    MODULE_REGISTRY,
    get_module,
    get_modules_by_category,
    RealTimeIntelligenceFeed,
    setup_security_routes,
)

# Optional external libraries: prefer real packages but provide lightweight fallbacks
try:
    import jwt  # type: ignore
except Exception:  # pragma: no cover - fallback for static analysis / dev

    class _JWTStub:
        class PyJWTError(Exception):
            pass

        @staticmethod
        def encode(payload, key, algorithm="HS256"):
            raise RuntimeError("jwt not available")

        @staticmethod
        def decode(token, key, algorithms=None):
            raise RuntimeError("jwt not available")

    jwt = _JWTStub  # type: ignore

try:
    import redis.asyncio as redis  # type: ignore
except Exception:  # pragma: no cover - dev fallback
    redis = None  # type: ignore

try:
    from elasticsearch import AsyncElasticsearch  # type: ignore
except Exception:  # pragma: no cover - dev fallback

    class AsyncElasticsearch:  # type: ignore
        def __init__(self, *args, **kwargs):
            pass

        async def close(self):
            pass

# FastAPI/pydantic fallbacks to keep static analysis stable in environments without packages.

# Use importlib to avoid a static "from fastapi import ..." that some editors/language servers
# flag when the package isn't installed; fall back to lightweight stubs if fastapi is absent.
_fastapi_spec = importlib.util.find_spec("fastapi")
if _fastapi_spec is not None:
    # fastapi is available at runtime; import the symbols we need.
    _fastapi = importlib.import_module("fastapi")
    Depends = getattr(_fastapi, "Depends")
    FastAPI = getattr(_fastapi, "FastAPI")
    HTTPException = getattr(_fastapi, "HTTPException")
    Request = getattr(_fastapi, "Request")
    WebSocket = getattr(_fastapi, "WebSocket")
    WebSocketDisconnect = getattr(_fastapi, "WebSocketDisconnect")

    # Try importing commonly used submodules; if any fail, provide minimal fallbacks.
    try:
        from fastapi.middleware.cors import CORSMiddleware  # type: ignore
    except Exception:
        CORSMiddleware = None  # type: ignore

    try:
        from fastapi.middleware.gzip import GZipMiddleware  # type: ignore
    except Exception:
        GZipMiddleware = None  # type: ignore

    try:
        from fastapi.responses import JSONResponse, FileResponse  # type: ignore
    except Exception:

        def JSONResponse(content=None, status_code=200):
            return {"status_code": status_code, "content": content}

        class FileResponse:  # type: ignore
            def __init__(self, *a, **k):
                pass

    try:
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer  # type: ignore
    except Exception:

        class HTTPAuthorizationCredentials:  # type: ignore
            credentials: str = ""

        class HTTPBearer:  # type: ignore
            def __init__(self, *a, **k):
                pass
else:
    # fastapi is not available; provide minimal stubs to keep static analysis and tests happy.
    def Depends(dependency=None):
        return None

    class HTTPBearer:
        def __init__(self, *a, **k):
            pass

    class HTTPAuthorizationCredentials:  # type: ignore
        credentials: str = ""

    class FastAPI:  # type: ignore
        def __init__(self, *a, **k):
            # Create state object with all required attributes
            class AppState:
                def __init__(self):
                    # Use broadly-typed attributes so static type checkers do not
                    # infer these as None-only; these will be populated with various
                    # runtime adapters (Redis client, ES client, Graph DB, etc.).
                    self.redis: Any = None
                    self.es: Any = None
                    self.ai_engine: Any = None
                    self.security_db: Any = None
                    self.investigation_manager: Any = None
                    self.reporting_engine: Any = None
                    self.report_scheduler: Any = None
                    self.graph_db: Any = None
                    self.intelligence_feeds: Any = None
                    self.ws_manager: Any = None
                    self.execution_engine: Any = None

            self.state = AppState()

        def add_middleware(self, *a, **k):
            pass

        def exception_handler(self, *a, **k):
            def _decorator(func):
                return func

            return _decorator

        def get(self, *a, **k):
            def _decorator(func):
                return func

            return _decorator

        def post(self, *a, **k):
            def _decorator(func):
                return func

            return _decorator

        def delete(self, *a, **k):
            def _decorator(func):
                return func

            return _decorator

        def websocket(self, *a, **k):
            def _decorator(func):
                return func

            return _decorator

    class HTTPException(Exception):
        def __init__(self, status_code=500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class Request:  # type: ignore
        scope = {}
        client = None

    class WebSocket:  # type: ignore
        async def accept(self):
            pass

        async def send_json(self, *a, **k):
            pass

        async def receive_json(self):
            return {}

    class WebSocketDisconnect(Exception):
        pass

    class CORSMiddleware:  # type: ignore
        pass

    class GZipMiddleware:  # type: ignore
        pass


# Type-only aliases for static type checking (no runtime impact)
if TYPE_CHECKING:
    pass


class AppConfig:
    """Application configuration - all secrets must be provided via environment variables"""

    # Critical: Fail fast if SECRET_KEY is not set
    # Accept both OSINT_SECRET_KEY (preferred) and SECRET_KEY (fallback) for compatibility
    SECRET_KEY = os.getenv("OSINT_SECRET_KEY") or os.getenv("SECRET_KEY")
    if (
        not SECRET_KEY
        or SECRET_KEY == "change-this-secret-key-in-production-environment"
        or SECRET_KEY == "changeme-secure-secret-key-minimum-32-chars"
        or SECRET_KEY == "your_very_long_random_secret_key_here_minimum_32_characters"
        or SECRET_KEY == "your_jwt_secret_key_here_minimum_32_characters"
    ):
        raise ValueError(
            "Either OSINT_SECRET_KEY or SECRET_KEY environment variable must be set to a secure random value. "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )

    # Database configuration with secure defaults only for local dev
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DATABASE_URL = os.getenv(
        "DATABASE_URL", "postgresql://user:pass@localhost/osint_db"
    )
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

    # AI configuration (optional)
    AI_MODEL_API_KEY = os.getenv("PERPLEXITY_API_KEY", "")
    AI_MODEL_URL = os.getenv("AI_MODEL_URL", "https://api.perplexity.ai")
    AI_MODEL_PROVIDER = os.getenv("AI_MODEL_PROVIDER", "perplexity")
    AI_MODEL_NAME = os.getenv("AI_MODEL_NAME", "llama-3.1-sonar-large-128k-online")

    # CORS configuration - allow customization via env
    cors_origins_str = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:8000"
    )
    CORS_ORIGINS = [origin.strip() for origin in cors_origins_str.split(",")]


# Ensure we have a valid base class to inherit from (handles pydantic fallback)
BaseModelBase = BaseModel


class InvestigationCreate(BaseModelBase):
    """Model for creating new investigations with input validation"""

    name: str = Field(
        ..., min_length=1, max_length=200, description="Investigation name"
    )
    description: Optional[str] = Field(
        None, max_length=2000, description="Investigation description"
    )
    targets: List[str] = Field(
        ..., min_length=1, max_length=100, description="List of targets to investigate"
    )
    investigation_type: str = Field(
        ...,
        pattern="^(domain|ip|email|phone|company|person)$",
        description="Type of investigation",
    )
    priority: str = Field(
        default="medium",
        pattern="^(low|medium|high|critical)$",
        description="Investigation priority level",
    )
    tags: List[str] = Field(default_factory=list, max_length=20)  # type: ignore[assignment]
    scheduled_start: Optional[datetime] = None
    auto_reporting: bool = True

    @classmethod
    def validate_name(cls, v):
        """Sanitize investigation name to prevent injection attacks"""
        import re

        if not v or not v.strip():
            raise ValueError("Investigation name cannot be empty")
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\';(){}]', "", v)
        if len(sanitized) != len(v):
            raise ValueError("Investigation name contains invalid characters")
        return sanitized.strip()

    @classmethod
    def validate_targets(cls, v):
        """Validate targets list"""
        if not v:
            raise ValueError("At least one target is required")
        # Check for duplicate targets
        if len(v) != len(set(v)):
            raise ValueError("Duplicate targets not allowed")
        # Basic validation for each target
        for target in v:
            if not target or not target.strip():
                raise ValueError("Empty target not allowed")
            if len(target) > 500:
                raise ValueError("Target value too long (max 500 characters)")
        return [t.strip() for t in v]


class OSINTTask(BaseModelBase):
    """Model for OSINT task execution"""

    task_id: str
    investigation_id: str
    task_type: str
    target: str
    status: str
    progress: float
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None


class AIAnalysisRequest(BaseModelBase):
    """Model for AI analysis requests"""

    investigation_id: str
    analysis_type: Literal["summary", "threat_assessment", "recommendations", "report"]
    context: Optional[str] = None
    include_raw_data: bool = Field(default=False)  # type: ignore[assignment]


class CapabilityModel(BaseModelBase):
    id: str
    name: str
    description: str
    category: str
    version: str
    inputs: Dict[str, str]
    produces: List[str]
    dependencies: List[str]
    cost_weight: float
    risk_level: str
    enabled: bool


class PlannedTaskModel(BaseModelBase):
    id: str
    capability_id: str
    inputs: Dict[str, str]
    depends_on: List[str]
    status: str


class PlanModel(BaseModelBase):
    investigation_id: str
    tasks: List[PlannedTaskModel]


class ModuleInfo(BaseModelBase):
    """Information about an OSINT module"""

    name: str
    description: str
    category: str
    class_name: str


class ModuleExecutionRequest(BaseModelBase):
    """Request to execute a module with parameters"""

    module_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)  # type: ignore[assignment]


class ModuleExecutionResponse(BaseModelBase):
    """Standardized response for module execution endpoints"""

    status: str
    module_name: Optional[str] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time: Optional[float] = None


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.investigation_subscribers: Dict[str, List[str]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]

        # Remove from investigation subscriptions
        for investigation_id in list(self.investigation_subscribers.keys()):
            subs = self.investigation_subscribers.get(investigation_id, [])
            if client_id in subs:
                subs.remove(client_id)
            if not subs:
                self.investigation_subscribers.pop(investigation_id, None)

    async def subscribe_to_investigation(self, client_id: str, investigation_id: str):
        self.investigation_subscribers.setdefault(investigation_id, [])
        if client_id not in self.investigation_subscribers[investigation_id]:
            self.investigation_subscribers[investigation_id].append(client_id)

    async def broadcast_investigation_update(
        self, investigation_id: str, data: Dict[str, Any]
    ):
        if investigation_id in self.investigation_subscribers:
            targets = [
                cid
                for cid in self.investigation_subscribers[investigation_id]
                if cid in self.active_connections
            ]
        else:
            # Fallback: broadcast to all active connections
            targets = list(self.active_connections.keys())

        for client_id in targets:
            try:
                await self.active_connections[client_id].send_json(
                    {
                        "type": "investigation_update",
                        "investigation_id": investigation_id,
                        "data": data,
                    }
                )
            except Exception as e:
                logging.error(f"Failed to send update to {client_id}: {e}")
                self.disconnect(client_id)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logging.info("🚀 Starting OSINT Suite API Server...")

    # Initialize connections (guard against missing redis/elasticsearch)
    try:
        app.state.redis = (
            redis.from_url(AppConfig.REDIS_URL) if redis is not None else None
        )
    except Exception as e:
        logging.warning(f"Failed to connect to Redis: {e}")
        app.state.redis = None

    try:
        app.state.es = AsyncElasticsearch([AppConfig.ELASTICSEARCH_URL])
    except Exception as e:
        logging.warning(f"Failed to connect to Elasticsearch: {e}")
        app.state.es = None

    # Initialize AI engine (only if API key is configured)
    if AppConfig.AI_MODEL_API_KEY:
        try:
            from local_llm_engine import LocalLLMEngine

            app.state.ai_engine = LocalLLMEngine()
            logging.info("🤖 Local LLM Engine initialized")
        except Exception:
            app.state.ai_engine = None
            logging.warning("⚠️ Local LLM Engine import failed; AI engine disabled")
    else:
        app.state.ai_engine = None
        logging.warning("⚠️  AI Engine not initialized - no API key configured")

    # Initialize Security Framework
    logging.info("🔐 Initializing Security Framework...")
    try:
        security_monitor.start_monitoring()
    except Exception:
        logging.warning("Security monitor failed to start")

    # Initialize Security Database (safe, well-indented)
    try:
        from security.security_database import SecurityDatabase

        app.state.security_db = SecurityDatabase()
        if hasattr(app.state.security_db, "initialize_schema"):
            try:
                app.state.security_db.initialize_schema()
            except Exception:
                logging.warning("Failed to initialize security DB schema")
        data_access_control.set_database(app.state.security_db)
        security_monitor.set_database(app.state.security_db)
        logging.info("✅ Security Framework initialized")
    except Exception:
        app.state.security_db = None
        logging.warning("Security database unavailable")

    # Instantiate persistent investigation store
    try:
        store = PersistentInvestigationStore()
    except Exception:
        # If store cannot be instantiated, set to None and continue with degraded functionality
        store = None
        logging.warning(
            "PersistentInvestigationStore unavailable; investigation manager disabled"
        )

    # Optional advanced manager instantiation
    if store is not None and InvestigationManager is not None:
        try:
            # attempt to wire advanced manager if available; failures are non-fatal
            from result_encryption import ResultEncryption  # type: ignore
            from osint_suite import OSINTSuite  # type: ignore
            from secrets_manager import SecretsManager  # type: ignore

            osint_suite = OSINTSuite()
            result_encryption = ResultEncryption()
            secrets_manager = SecretsManager()

            advanced_manager = InvestigationManager(
                osint_suite=osint_suite,
                audit_trail=audit_trail,
                result_encryption=result_encryption,
                secrets_manager=secrets_manager,
                storage_path="./advanced_investigations",
            )
            # attach only if method exists
            if hasattr(store, "attach_advanced_manager"):
                store.attach_advanced_manager(advanced_manager)
                logging.info("Advanced InvestigationManager initialized and attached.")
        except Exception as e:
            logging.warning(f"Advanced manager unavailable: {e}")

    app.state.investigation_manager = store

    # Initialize reporting engine and scheduler
    try:
        app.state.reporting_engine = EnhancedReportingEngine(
            ai_engine=app.state.ai_engine
        )
        app.state.report_scheduler = ReportScheduler(app.state.reporting_engine)
        await app.state.report_scheduler.start_scheduler()
    except Exception:
        try:
            app.state.reporting_engine = EnhancedReportingEngine(ai_engine=None)
            app.state.report_scheduler = ReportScheduler(app.state.reporting_engine)
        except Exception:
            app.state.reporting_engine = None
            app.state.report_scheduler = None
        logging.warning(
            "Reporting engine or scheduler initialization failed or partially degraded"
        )

    # Initialize graph database (optional)
    try:
        graph_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        graph_user = os.getenv("NEO4J_USER", "neo4j")
        graph_password = os.getenv("NEO4J_PASSWORD", "change-this-default-password")

        app.state.graph_db = GraphDatabaseAdapter(graph_uri, graph_user, graph_password)
        graph_connected = await app.state.graph_db.connect()
        if graph_connected:
            logging.info("✅ Graph database connected")
        else:
            logging.warning(
                "⚠️  Graph database not available - relationship mapping disabled"
            )
    except Exception:
        logging.warning("⚠️  Graph database not available")
        app.state.graph_db = None

    # Initialize WebSocket manager
    app.state.ws_manager = WebSocketManager()

    # Initialize intelligence feeds
    try:
        app.state.intelligence_feeds = RealTimeIntelligenceFeed()
    except Exception:
        app.state.intelligence_feeds = None
        logging.warning("Real-time intelligence feeds unavailable")

    # Initialize execution engine
    try:
        app.state.execution_engine = ExecutionEngine(
            store=app.state.investigation_manager
        )
    except Exception:
        app.state.execution_engine = None
        logging.warning("Execution engine unavailable")

    # Set up event callback for WebSocket broadcasts
    def _event_callback(event_type: str, payload: Dict[str, Any]):
        # schedule broadcast without awaiting here
        try:
            coro = app.state.ws_manager.broadcast_investigation_update(
                payload.get("investigation_id"), payload
            )
            asyncio.create_task(coro)
        except Exception as e:
            logging.error(f"Failed to schedule ws broadcast: {e}")

        # Use event_type to avoid unused variable warning
        _ = event_type

    try:
        yield
    finally:
        # Shutdown sequence (perform async closes where appropriate)
        try:
            if getattr(app.state, "report_scheduler", None) and hasattr(
                app.state.report_scheduler, "stop_scheduler"
            ):
                await app.state.report_scheduler.stop_scheduler()
        except Exception:
            logging.exception("Error stopping report scheduler")

        try:
            if getattr(app.state, "es", None) and hasattr(app.state.es, "close"):
                await app.state.es.close()
        except Exception:
            logging.exception("Error closing elasticsearch client")

        try:
            if getattr(app.state, "graph_db", None) and hasattr(
                app.state.graph_db, "disconnect"
            ):
                await app.state.graph_db.disconnect()
        except Exception:
            logging.exception("Error disconnecting graph database")

        try:
            if getattr(app.state, "redis", None):
                # Close async redis connection
                try:
                    # redis.asyncio provides aclose() or close() methods
                    if hasattr(app.state.redis, "aclose"):
                        await app.state.redis.aclose()
                    elif hasattr(app.state.redis, "close"):
                        await app.state.redis.close()
                except Exception:
                    logging.exception("Error closing redis connection")
        except Exception:
            logging.exception("Error while cleaning up redis")

        logging.info("🛑 OSINT Suite API Server shutdown complete")


app = FastAPI(
    title="OSINT Suite API",
    description="Advanced OSINT Suite API with AI integration and real-time intelligence",
    version="2.0.0",
    lifespan=lifespan,
)

# Initialize Rate Limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    logging.info("✅ Rate limiting initialized")
except ImportError:
    logging.warning("⚠️  slowapi not installed - rate limiting disabled")

    # Create a no-op limiter for compatibility
    class NoOpLimiter:
        def limit(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    limiter = NoOpLimiter()  # type: ignore
    app.state.limiter = limiter
except Exception as e:
    logging.error(f"Failed to initialize rate limiter: {e}")
    limiter = NoOpLimiter()  # type: ignore
    app.state.limiter = limiter

# Initialize Security Framework Middleware
try:
    # app = init_security_middleware(cast(Any, app))  # type: ignore
    pass  # Security middleware initialization skipped
except Exception:
    logging.warning("Security middleware initialization skipped")

# Additional Middleware
try:
    if CORSMiddleware is not None:
        app.add_middleware(
            cast(Any, CORSMiddleware),
            allow_origins=AppConfig.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            # Restrict allowed headers for security
            allow_headers=[
                "Content-Type",
                "Authorization",
                "X-Request-ID",
                "X-Client-Info",
            ],
        )

    if GZipMiddleware is not None:
        app.add_middleware(cast(Any, GZipMiddleware), minimum_size=1000)

    logging.info("✅ Middleware initialized")
except Exception as e:
    logging.error(f"Middleware registration failed: {e}")

# ============================================================================
# Rate Limiting and Authentication
# ============================================================================


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
) -> Optional[str]:
    """Get current authenticated user from security framework"""
    try:
        user_obj = security_controller.get_current_user(cast(Any, credentials))
    except Exception:
        user_obj = None

    # Normalize to a user id string if possible
    if user_obj is None:
        return None
    if isinstance(user_obj, str):
        return user_obj
    if isinstance(user_obj, dict):
        for key in ("id", "user_id", "sub", "username", "name"):
            val = user_obj.get(key)
            if isinstance(val, str) and val:
                return val
        return None
    for key in ("id", "user_id", "sub", "username", "name"):
        if hasattr(user_obj, key):
            val = getattr(user_obj, key)
            if isinstance(val, str) and val:
                return val
    return None


async def require_authentication(current_user=Depends(get_current_user)):
    """Require authentication for endpoint"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user


async def require_permission(resource: str, action: str):
    """Create permission requirement decorator"""

    async def permission_checker(current_user=Depends(get_current_user)):
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        if not rbac_manager.check_permission(current_user, f"{resource}:{action}"):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions for {resource}:{action}",
            )
        return current_user

    return permission_checker


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
) -> str:
    """Verify a JWT token and return the subject (user id)."""
    if not credentials or not getattr(credentials, "credentials", None):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = credentials.credentials
    try:
        payload = jwt.decode(token, AppConfig.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except Exception:
        # Normalize all JWT decode errors to a 401 to avoid leaking internals
        raise HTTPException(status_code=401, detail="Invalid token")


def rate_limit(limit: int, window_seconds: int):
    """Create a rate limiting dependency that also verifies authentication.

    This combines authentication verification with rate limiting.
    Returns the user_id if both authentication and rate limiting pass.
    """

    async def rate_limit_dependency(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Optional[str]:
        # First verify authentication
        if not credentials or not getattr(credentials, "credentials", None):
            raise HTTPException(status_code=401, detail="Authentication required")

        token = credentials.credentials
        try:
            payload = jwt.decode(token, AppConfig.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("sub")
            if user_id is None:
                raise HTTPException(status_code=401, detail="Invalid token")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Then check rate limiting (simplified implementation)
        # In a real implementation, you'd use Redis or another store for distributed rate limiting
        current_time = int(time.time())
        rate_key = f"rate_limit:{user_id}:{current_time // window_seconds}"

        # For now, we'll use a simple in-memory approach
        # This is not suitable for production with multiple server instances
        global _rate_limits
        if "_rate_limits" not in globals():
            _rate_limits = {}

        if rate_key not in _rate_limits:
            _rate_limits[rate_key] = 0

        if _rate_limits[rate_key] >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Maximum {limit} requests per {window_seconds} seconds.",
            )

        _rate_limits[rate_key] += 1

        # Clean up old rate limit entries (simple cleanup)
        cutoff_time = current_time - window_seconds
        old_keys = [
            k
            for k in _rate_limits.keys()
            if int(k.split(":")[-1]) * window_seconds < cutoff_time
        ]
        for old_key in old_keys:
            del _rate_limits[old_key]

        return user_id

    return rate_limit_dependency


# ============================================================================
# API Routes
# ============================================================================


@app.get("/api/health")
@limiter.limit("300/minute")  # Higher limit for health checks
async def health_check(request: Request):
    """Primary health check endpoint consumed by dashboard ribbon."""
    # Basic service status placeholders (assume connected if objects exist)
    redis_status = "connected" if getattr(app.state, "redis", None) else "unknown"
    es_status = "connected" if getattr(app.state, "es", None) else "unknown"
    ai_status = "ready" if getattr(app.state, "ai_engine", None) else "uninitialized"
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "services": {
            "redis": redis_status,
            "elasticsearch": es_status,
            "ai_engine": ai_status,
        },
    }


@app.get("/api/health/detailed")
@limiter.limit("60/minute")
async def detailed_health_check(request: Request):
    """Detailed health check with service connectivity tests."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "services": {},
        "degraded_services": [],
    }

    # Check Redis
    try:
        if app.state.redis:
            await asyncio.wait_for(app.state.redis.ping(), timeout=2.0)
            health_status["services"]["redis"] = {
                "status": "healthy",
                "response_time_ms": "<2000",
            }
        else:
            health_status["services"]["redis"] = {"status": "not_configured"}
    except asyncio.TimeoutError:
        health_status["services"]["redis"] = {
            "status": "timeout",
            "error": "Connection timeout",
        }
        health_status["degraded_services"].append("redis")
        health_status["status"] = "degraded"
    except Exception as e:
        health_status["services"]["redis"] = {"status": "unhealthy", "error": str(e)}
        health_status["degraded_services"].append("redis")
        health_status["status"] = "degraded"

    # Check Elasticsearch
    try:
        if app.state.es:
            health_status["services"]["elasticsearch"] = {"status": "configured"}
        else:
            health_status["services"]["elasticsearch"] = {"status": "not_configured"}
    except Exception as e:
        health_status["services"]["elasticsearch"] = {
            "status": "error",
            "error": str(e),
        }

    # Check AI Engine
    health_status["services"]["ai_engine"] = {
        "status": "ready" if app.state.ai_engine else "not_configured"
    }

    # Check Graph DB
    try:
        if app.state.graph_db:
            health_status["services"]["graph_db"] = {"status": "configured"}
        else:
            health_status["services"]["graph_db"] = {"status": "not_configured"}
    except Exception:
        health_status["services"]["graph_db"] = {"status": "not_configured"}

    return health_status


def _tor_control_command(
    action: Literal["enable", "disable", "new_identity"]
) -> Tuple[bool, str, Dict[str, Any], int]:
    """Execute a Tor control port command and return status details.

    Returns a tuple of (success flag, human-readable message, tor status dict, HTTP status code).
    """

    status = get_tor_status()
    if not status.get("active"):
        return (
            False,
            "Tor control port is not reachable. Ensure Tor is running and the control port is enabled.",
            status,
            503,
        )

    try:
        from stem import Signal  # type: ignore
        from stem.control import Controller  # type: ignore
    except ImportError:
        return (
            False,
            "Tor control commands require the 'stem' package. Install it to manage Tor from the UI.",
            status,
            501,
        )

    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            if action == "enable":
                controller.set_conf("DisableNetwork", "0")
                message = "Tor network enabled; new circuits will build shortly."
            elif action == "disable":
                controller.set_conf("DisableNetwork", "1")
                message = "Tor network disabled via control port."
            else:  # action == "new_identity"
                controller.signal(Signal.NEWNYM)
                message = "Requested a new Tor identity (NEWNYM signal sent)."

    except Exception as exc:  # pragma: no cover - depends on local Tor configuration
        logging.exception("Tor control command '%s' failed", action)
        refreshed_status = get_tor_status()
        return (
            False,
            f"Unable to {action.replace('_', ' ')} due to an internal error.",
            refreshed_status,
            500,
        )

    refreshed_status = get_tor_status()
    return True, message, refreshed_status, 200


@app.get("/tor/status")
async def tor_status():
    """Expose Tor proxy status (no external network calls)."""
    status = get_tor_status()
    proxy_reachable = status.get("active", False)
    status["proxy_reachable"] = proxy_reachable
    status["timestamp"] = datetime.now().isoformat()
    return status


@app.get("/api/system/status")
async def system_status_alias(request: Request):
    """Alias for /api/health to match frontend expectations."""
    return await health_check(request)


@app.get("/health")
@limiter.limit("300/minute")  # Higher limit for health checks
async def health_fallback(request: Request):
    """Fallback health endpoint without /api prefix for compatibility."""
    return await health_check(request)


@app.get("/api/anonymity/tor/status")
async def anonymity_tor_status():
    """Alias for /tor/status under /api/anonymity path."""
    return await tor_status()


@app.post("/api/anonymity/tor/enable")
async def anonymity_tor_enable():
    """Enable Tor networking via the control port."""

    success, message, status, status_code = _tor_control_command("enable")
    return JSONResponse(
        {"success": success, "message": message, "status": status}, status_code=status_code
    )


@app.post("/api/anonymity/tor/disable")
async def anonymity_tor_disable():
    """Disable Tor networking via the control port."""

    success, message, status, status_code = _tor_control_command("disable")
    return JSONResponse(
        {"success": success, "message": message, "status": status}, status_code=status_code
    )


@app.post("/api/anonymity/tor/new-identity")
async def anonymity_tor_new_identity():
    """Request a new Tor identity using the NEWNYM signal."""

    success, message, status, status_code = _tor_control_command("new_identity")
    return JSONResponse(
        {"success": success, "message": message, "status": status}, status_code=status_code
    )


@app.get("/api/capabilities", response_model=List[CapabilityModel])
async def list_capabilities():
    """List registered capabilities (static registry for now)."""
    out = []
    for cap_id, cap in CAPABILITY_REGISTRY.items():
        out.append(
            CapabilityModel(
                id=cap.id,
                name=cap.name,
                description=cap.description,
                category=cap.category,
                version=cap.version,
                inputs=cap.inputs,
                produces=list(cap.produces),
                dependencies=list(cap.dependencies),
                cost_weight=cap.cost_weight,
                risk_level=cap.risk_level,
                enabled=cap.enabled,
            )
        )
    return out


@app.get("/api/investigations/{investigation_id}/plan", response_model=PlanModel)
async def get_investigation_plan(
    investigation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Return (build if absent) the plan for an investigation."""
    store = app.state.investigation_manager
    # Load investigation to verify ownership
    inv = await store.get_investigation(investigation_id, owner_id=user_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Try to get or build plan
    try:
        # Use the same adapter module path as imported at top
        from investigations.investigation_adapter import (  # type: ignore
            PersistentInvestigationStore,
        )

        if isinstance(store, PersistentInvestigationStore) and hasattr(
            store, "_load_or_build_plan"
        ):
            plan = store._load_or_build_plan(store._items[investigation_id])  # type: ignore[attr-defined]
        else:
            planner = Planner()
            plan = planner.build_plan(
                investigation_id, inv["investigation_type"], inv["targets"]
            )  # type: ignore
    except Exception:
        # Fallback: create a basic plan if advanced planning fails
        planner = Planner()
        plan = planner.build_plan(
            investigation_id, inv["investigation_type"], inv["targets"]
        )  # type: ignore

    # Extract tasks from plan
    plan_id = (
        getattr(plan, "investigation_id", None)
        or getattr(plan, "id", None)
        or investigation_id
    )
    task_iter = getattr(plan, "tasks", None) or (
        plan.get("tasks", []) if isinstance(plan, dict) else []
    )

    tasks_out: List[PlannedTaskModel] = []
    for t in task_iter:
        tasks_out.append(
            PlannedTaskModel(
                id=str(
                    getattr(
                        t,
                        "id",
                        getattr(
                            t, "task_id", t.get("id") if isinstance(t, dict) else ""
                        ),
                    )
                ),
                capability_id=str(
                    getattr(
                        t,
                        "capability_id",
                        getattr(
                            t,
                            "capability",
                            t.get("capability_id") if isinstance(t, dict) else "",
                        ),
                    )
                ),
                inputs=(
                    getattr(t, "inputs", t.get("inputs") if isinstance(t, dict) else {})
                    or {}
                ),
                depends_on=(
                    getattr(
                        t,
                        "depends_on",
                        t.get("depends_on") if isinstance(t, dict) else [],
                    )
                    or []
                ),
                status=str(
                    getattr(
                        t,
                        "status",
                        getattr(
                            t,
                            "state",
                            t.get("status") if isinstance(t, dict) else "unknown",
                        ),
                    )
                ),
            )
        )

    return PlanModel(investigation_id=str(plan_id), tasks=tasks_out)


@app.post("/api/investigations/{investigation_id}/execute/all")
async def execute_all_tasks(
    investigation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    inv = await app.state.investigation_manager.get_investigation(
        investigation_id, owner_id=user_id
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await app.state.execution_engine.run_all(investigation_id)
    return {"message": "Execution complete"}


@app.get("/api/investigations/{investigation_id}/evidence/provenance")
async def investigation_provenance(
    investigation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    inv = await app.state.investigation_manager.get_investigation(
        investigation_id, owner_id=user_id
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    from evidence.store import get_default_store

    prov = compute_investigation_provenance(get_default_store(), investigation_id)
    return prov


# ============================================================================
# Geospatial Intelligence (Placeholder Endpoint)
# ============================================================================


@app.get("/api/geo")
async def geo_snapshot():
    """Return a lightweight snapshot of geospatial intelligence data.
    Currently returns placeholder points and flight routes for the mapping
    widget. In future iterations this will aggregate:
      * Resolved IP geolocations (network / infrastructure module)
      * Flight paths (aviation intelligence module)
      * Potential infrastructure relationship lines

    Response schema:
    {
      "generated_at": ISO8601,
      "ip_points": [ { ip, lat, lon, asn, label } ],
                    "flight_routes": [
                        {
                            flight,
                            from: {icao,lat,lon,city},
                            to: {...},
                            path: [[lat,lon],...],
                            status
                        }
                    ]
    }
    This endpoint is unauthenticated for rapid internal dashboard rendering.
    DO NOT expose publicly without access controls.
    """
    # Placeholder sample data; coordinates approximate.
    ip_points = [
        {
            "ip": "8.8.8.8",
            "lat": 37.751,
            "lon": -97.822,
            "asn": "AS15169",
            "label": "Public DNS",
        },
        {
            "ip": "1.1.1.1",
            "lat": -33.494,
            "lon": 143.2104,
            "asn": "AS13335",
            "label": "Resolver",
        },
        {
            "ip": "203.0.113.10",
            "lat": 51.509,
            "lon": -0.118,
            "asn": "AS64500",
            "label": "Sample Infra",
        },
    ]

    flight_routes = [
        {
            "flight": "AB123",
            "from": {
                "icao": "KJFK",
                "lat": 40.6413,
                "lon": -73.7781,
                "city": "New York",
            },
            "to": {
                "icao": "EGLL",
                "lat": 51.4700,
                "lon": -0.4543,
                "city": "London",
            },
            "path": [
                [40.6413, -73.7781],
                [45.0, -50.0],  # Mid-Atlantic waypoint (approx)
                [51.4700, -0.4543],
            ],
            "status": "enroute",
        }
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ip_points": ip_points,
        "flight_routes": flight_routes,
    }


@app.post("/api/investigations")
async def create_investigation(
    investigation: InvestigationCreate,
    user_id: Optional[str] = Depends(rate_limit(limit=15, window_seconds=60)),
):
    """Create a new OSINT investigation"""
    try:
        # Ensure the dependency provided a user id (rate_limit may return None)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        # Validate OPSEC policies
        for target in investigation.targets:
            policy_result = enforce_policy(
                operation_type="investigation_create", target=target, actor=user_id
            )
            if not policy_result["allowed"]:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "OPSEC policy violation for target "
                        f"{target}: {policy_result['reason']}"
                    ),
                )

        # Create investigation
        investigation_id = await app.state.investigation_manager.create_investigation(
            name=investigation.name,
            description=investigation.description,
            targets=investigation.targets,
            investigation_type=investigation.investigation_type,
            priority=investigation.priority,
            tags=investigation.tags,
            owner_id=user_id,
            scheduled_start=investigation.scheduled_start,
            auto_reporting=investigation.auto_reporting,
        )

        # Log audit trail
        audit_trail.log_operation(
            operation="investigation_created",
            actor=user_id,
            target=investigation_id,
            metadata={
                "name": investigation.name,
                "targets": investigation.targets,
                "type": investigation.investigation_type,
            },
        )

        return {
            "investigation_id": investigation_id,
            "status": "created",
            "message": "Investigation created successfully",
        }

    except Exception as e:
        logging.error(f"Failed to create investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigations")
async def list_investigations(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    include_archived: bool = False,
    include_meta: bool = False,
    user_id: Optional[str] = Depends(verify_token),
):
    """List user's investigations with optional filters and metadata.

    Query Params:
      skip, limit: pagination window
      status: optional status filter (created|running|completed|archived)
      include_archived: if true include archived items alongside active
      include_meta: if true wrap items with {items:[], meta:{total,skip,limit}}
    """
    try:
        result = await app.state.investigation_manager.list_investigations(
            owner_id=user_id,
            skip=skip,
            limit=limit,
            status_filter=status,
            include_archived=include_archived,
            include_meta=include_meta,
        )
        return result
    except Exception as e:
        logging.error(f"Failed to list investigations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Get investigation details with results"""
    try:
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=investigation_id, owner_id=user_id
        )
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        return investigation
    except Exception as e:
        logging.error(f"Failed to get investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigations/{investigation_id}/start")
async def start_investigation(
    investigation_id: str,
    user_id: Optional[str] = Depends(rate_limit(limit=30, window_seconds=300)),
):
    """Start OSINT investigation execution"""
    try:
        # Start investigation
        await app.state.investigation_manager.start_investigation(
            investigation_id=investigation_id, owner_id=user_id
        )

        # Broadcast real-time update
        await app.state.ws_manager.broadcast_investigation_update(
            investigation_id=investigation_id,
            data={
                "type": "investigation_started",
                "status": "running",
                "message": "Investigation started",
                "investigation_id": investigation_id,
            },
        )

        return {"status": "started", "investigation_id": investigation_id}
    except Exception as e:
        logging.error(f"Failed to start investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigations/{investigation_id}/archive")
async def archive_investigation_endpoint(
    investigation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Archive an investigation for the authenticated owner."""

    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    store = app.state.investigation_manager
    if store is None:
        raise HTTPException(
            status_code=503, detail="Investigation manager unavailable"
        )

    investigation_name: Optional[str] = None
    advanced_id: Optional[str] = None
    archived_at: Optional[str] = None

    try:
        if isinstance(store, PersistentInvestigationStore):
            investigation = await store.get_investigation(
                investigation_id, owner_id=user_id
            )
            if not investigation:
                raise HTTPException(status_code=404, detail="Investigation not found")

            investigation_name = investigation.get("name")
            advanced_id = investigation.get("advanced_id")

            if investigation.get("archived") or investigation.get("status") == "archived":
                archived_at = investigation.get("archived_at")
                return {
                    "status": "archived",
                    "investigation_id": investigation_id,
                    "archived_at": archived_at,
                    "message": "Investigation already archived",
                }

            result = await store.archive_investigation(investigation_id, owner_id=user_id)
            archived_at = result.get("archived_at")
            advanced_id = result.get("advanced_id") or advanced_id
        else:
            archive_callable = getattr(store, "archive_investigation", None) or getattr(
                store, "archive", None
            )
            if not archive_callable:
                raise HTTPException(
                    status_code=400, detail="Archiving not supported for this store"
                )

            archive_result = await archive_callable(investigation_id)
            if isinstance(archive_result, dict):
                archived_at = archive_result.get("archived_at")
            try:
                investigation_obj = await store.get_investigation(investigation_id)  # type: ignore[arg-type]
                if investigation_obj is None:
                    raise HTTPException(
                        status_code=404, detail="Investigation not found"
                    )
                investigation_name = getattr(investigation_obj, "name", None)
            except TypeError:
                # Some implementations may require owner id; fall back to None
                investigation_name = None
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except Exception as e:
        logging.error(f"Failed to archive investigation {investigation_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to archive investigation")

    # If an advanced manager is attached, archive the mirrored investigation as well
    if isinstance(store, PersistentInvestigationStore):
        advanced_manager = getattr(store, "advanced_manager", None)
        if advanced_manager and advanced_id:
            try:
                adv_result = await advanced_manager.archive_investigation(advanced_id)
                if isinstance(adv_result, dict) and not archived_at:
                    archived_at = adv_result.get("archived_at")
            except Exception as e:  # pragma: no cover - best-effort archival
                logging.warning(
                    "Advanced investigation archive failed for %s: %s",
                    advanced_id,
                    e,
                )

    if archived_at is None:
        archived_at = datetime.now(timezone.utc).isoformat()

    # Log audit trail entry for archival
    try:
        audit_trail.log_operation(
            operation="investigation_archived",
            actor=user_id,
            target=investigation_id,
            metadata={
                "name": investigation_name,
                "archived_at": archived_at,
            },
        )
    except Exception as e:  # pragma: no cover - logging should not fail request
        logging.warning(f"Audit logging failed for investigation archive: {e}")

    # Broadcast WebSocket notification about archived status
    if getattr(app.state, "ws_manager", None):
        try:
            await app.state.ws_manager.broadcast_investigation_update(
                investigation_id=investigation_id,
                data={
                    "type": "investigation_archived",
                    "status": "archived",
                    "message": "Investigation archived",
                    "investigation_id": investigation_id,
                    "archived_at": archived_at,
                    "investigation_name": investigation_name,
                    "updates": {
                        "status": "archived",
                        "archived_at": archived_at,
                    },
                },
            )
        except Exception as e:  # pragma: no cover - notification best effort
            logging.warning(
                "WebSocket broadcast failed for investigation %s archive: %s",
                investigation_id,
                e,
            )

    return {
        "status": "archived",
        "investigation_id": investigation_id,
        "archived_at": archived_at,
        "message": "Investigation archived successfully",
    }


@app.get("/api/investigations/{investigation_id}/tasks")
async def investigation_tasks(
    investigation_id: str,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    include_meta: bool = False,
    user_id: Optional[str] = Depends(verify_token),
):
    """Return detailed (optionally filtered/paginated) task list.

    Query params:
      skip, limit: pagination window.
      status: optional status filter
      task_type: optional task type filter
      include_meta: if true include metadata
    """
    try:
        tasks = await app.state.investigation_manager.list_tasks(
            owner_id=user_id,
            investigation_id=investigation_id,
            skip=skip,
            limit=limit,
            status=status,
            task_type=task_type,
            include_meta=include_meta,
        )

        # Accept either a dict container or a list; if dict ensure investigation matches
        if (
            isinstance(tasks, dict)
            and tasks.get("investigation_id") != investigation_id
        ):
            raise HTTPException(status_code=404, detail="Investigation not found")

        return tasks
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to get tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/modules")
async def list_modules():
    """List all available OSINT modules with their metadata."""
    modules = []
    for name, info in MODULE_REGISTRY.items():
        modules.append(
            ModuleInfo(
                name=name,
                description=info["description"],
                category=info["category"],
                class_name=info["class"].__name__,
            )
        )
    return modules


@app.get("/api/modules/categories")
async def list_module_categories():
    """List all available module categories."""
    return {"categories": list(CATEGORIES.keys())}


@app.get("/api/modules/category/{category}", response_model=List[ModuleInfo])
async def get_modules_by_category_endpoint(category: str):
    """Get all modules in a specific category."""
    if category not in CATEGORIES:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found")
    modules = []
    for name, info in MODULE_REGISTRY.items():
        if info["category"] == category:
            modules.append(
                ModuleInfo(
                    name=name,
                    description=info["description"],
                    category=info["category"],
                    class_name=info["class"].__name__,
                )
            )
    return modules


@app.post("/api/modules/execute")
async def execute_module(
    request: ModuleExecutionRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Execute an OSINT module with given parameters."""
    import time

    start_time = time.time()
    try:
        # Get the module instance
        module_instance = get_module(request.module_name)
        if module_instance is None:
            raise HTTPException(
                status_code=404, detail=f"Module '{request.module_name}' not found"
            )

        # Log the operation
        audit_trail.log_operation(
            operation="module_execute",
            actor=user_id or "anonymous",
            target=f"module:{request.module_name}",
            metadata={"parameters": request.parameters},
        )

        # Execute the module based on its type
        result = None

        # Priority list of execution methods to check
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
        method_found = False
        for method_name in execution_methods:
            if hasattr(module_instance, method_name):
                method = getattr(module_instance, method_name)
                result = method(**request.parameters)
                method_found = True
                break

        # If no specific method found, try pattern-based methods
        if not method_found:
            # Get all callable methods that match execution patterns
            method_patterns = [
                "analyze_",
                "search_",
                "scan_",
                "track_",
                "monitor_",
                "comprehensive_",
            ]
            module_methods = [
                m
                for m in dir(module_instance)
                if callable(getattr(module_instance, m)) and not m.startswith("_")
            ]

            # Find the first method that matches our patterns
            execution_method = None
            for method_name in module_methods:
                if any(method_name.startswith(pattern) for pattern in method_patterns):
                    execution_method = method_name
                    break

            if execution_method:
                method = getattr(module_instance, execution_method)
                result = method(**request.parameters)
                method_found = True

        if not method_found:
            raise HTTPException(
                status_code=400,
                detail=f"Module '{request.module_name}' does not have a supported execution method. "
                f"Expected one of: {', '.join(execution_methods)}",
            )

        execution_time = time.time() - start_time

        return ModuleExecutionResponse(
            status="success",
            module_name=request.module_name,
            result=result,
            execution_time=execution_time,
        )

    except ValueError as e:
        # Module not found
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        execution_time = time.time() - start_time

        # Log the error
        audit_trail.log_operation(
            operation="module_execute_error",
            actor=user_id or "anonymous",
            target=f"module:{request.module_name}",
            metadata={"error": str(e), "parameters": request.parameters},
        )

        return ModuleExecutionResponse(
            status="error",
            module_name=request.module_name,
            error=str(e),
            execution_time=execution_time,
        )


@app.get("/api/modules/{module_name}")
async def get_module_info(module_name: str):
    """Get detailed information about a specific module."""
    if module_name not in MODULE_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")

    info = MODULE_REGISTRY[module_name]
    return {
        "name": module_name,
        "description": info["description"],
        "category": info["category"],
        "class_name": info["class"].__name__,
        "methods": [
            method for method in dir(info["class"]) if not method.startswith("_")
        ],
    }


# =========================================================================
# Dev Helper Endpoint (JWT issuance) - guarded by env flag
# =========================================================================


@app.post("/api/dev/token")
async def dev_token(sub: str = "dev-user", expires_minutes: int = 60):
    """Issue a development JWT for local VS Code extension.
    Enabled ONLY in development mode with ENABLE_DEV_AUTH=1.
    NEVER enable this in production.
    """
    # Strict environment check - must be development AND explicitly enabled
    if AppConfig.ENVIRONMENT != "development":
        raise HTTPException(status_code=404, detail="Not found")

    if os.getenv("ENABLE_DEV_AUTH") != "1":
        raise HTTPException(status_code=403, detail="Dev auth disabled")

    # Log security warning
    logging.warning(
        f"DEV AUTH: Issuing development token for user={sub}. "
        "This should NEVER happen in production!"
    )

    now = datetime.utcnow()
    payload = {
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "scopes": ["investigations:read", "investigations:write"],
        "env": "development",  # Mark as dev token
    }
    token = jwt.encode(payload, AppConfig.SECRET_KEY, algorithm="HS256")
    return {
        "token": token,
        "expires_in": expires_minutes * 60,
        "warning": "Development token only",
    }


@app.post("/api/ai/analyze")
async def ai_analysis(
    request: AIAnalysisRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Request AI analysis of investigation data"""
    try:
        # Get investigation data
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=request.investigation_id, owner_id=user_id
        )

        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Perform AI analysis
        analysis_result = await app.state.ai_engine.analyze_investigation(
            investigation_data=investigation,
            analysis_type=request.analysis_type,
            context=request.context,
            include_raw_data=request.include_raw_data,
        )

        # Store analysis result
        await app.state.investigation_manager.store_ai_analysis(
            investigation_id=request.investigation_id,
            analysis_type=request.analysis_type,
            result=analysis_result,
        )

        return analysis_result

    except Exception as e:
        logging.error(f"AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reports/generate")
async def generate_report(
    investigation_id: str,
    report_type: str = "executive_summary",
    format: str = "pdf",
    include_charts: bool = True,
    user_id: Optional[str] = Depends(rate_limit(limit=5, window_seconds=300)),
):
    """Generate investigation report with enhanced features"""
    try:
        # Get investigation
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=investigation_id, owner_id=user_id
        )

        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Generate enhanced report data
        if report_type == "executive_summary":
            report_data = app.state.reporting_engine.generate_executive_summary(
                investigation
            )
        else:
            # For other report types, use the existing method or create comprehensive report
            report_data = {
                "investigation_id": investigation_id,
                "generated_at": datetime.now().isoformat(),
                "title": f"{report_type.replace('_', ' ').title()} Report",
                "executive_summary": f"Comprehensive {report_type} analysis for investigation {investigation_id}",
                "key_findings": [
                    "Investigation data analysis",
                    "Intelligence correlation",
                    "Risk assessment",
                ],
                "recommendations": [
                    "Review findings",
                    "Implement security measures",
                    "Monitor ongoing activity",
                ],
            }

        # Generate PDF if requested
        if format == "pdf":
            pdf_path = app.state.reporting_engine.generate_pdf_report(
                report_data,
                template_name=report_type,
                filename=f"report_{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            )

            return {
                "report_id": f"report_{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "download_url": f"/api/reports/download/{os.path.basename(pdf_path)}",
                "format": "pdf",
                "generated_at": datetime.now().isoformat(),
                "file_path": pdf_path,
            }

        # Return JSON report
        return {
            "report_data": report_data,
            "format": "json",
            "generated_at": datetime.now().isoformat(),
        }

    except Exception as e:
        logging.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/download/{filename}")
async def download_report(filename: str):
    """Download generated report file"""
    try:
        from fastapi.responses import FileResponse

        reports_dir = Path("output/reports")
        file_path = reports_dir / filename

        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Report file not found")

        return FileResponse(
            path=file_path, filename=filename, media_type="application/pdf"
        )

    except Exception as e:
        logging.error(f"Report download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reports/schedule")
async def schedule_report(
    schedule_data: Dict[str, Any],
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Schedule recurring reports"""
    # Ensure the dependency provided a user id (verify_token may return None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        # Try the canonical package locations first (matches other imports above)
        try:
            from reporting.reporting_engine import ReportSchedule  # type: ignore
        except Exception:
            try:
                from reporting.report_scheduler import ReportSchedule  # type: ignore
            except Exception:
                # Minimal fallback dataclass for environments where the reporting
                # package is not installed; keeps the API usable for basic scheduling.
                from dataclasses import dataclass, field
                from typing import Optional, Dict, Any, List

                @dataclass
                class ReportSchedule:
                    report_id: str
                    name: str
                    template: str
                    frequency: str
                    recipients: List[str]
                    filters: Dict[str, Any] = field(default_factory=dict)
                    enabled: bool = True
                    next_run: Optional[datetime] = None

        schedule = ReportSchedule(
            report_id=schedule_data.get(
                "report_id", f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            ),
            name=schedule_data["name"],
            template=schedule_data.get("template", "executive_summary"),
            frequency=schedule_data["frequency"],  # daily, weekly, monthly
            recipients=schedule_data["recipients"],
            filters=schedule_data.get("filters", {}),
            enabled=schedule_data.get("enabled", True),
        )

        schedule_id = await app.state.report_scheduler.schedule_report(schedule)

        return {
            "schedule_id": schedule_id,
            "next_run": schedule.next_run.isoformat() if schedule.next_run else None,
            "status": "scheduled",
        }

    except Exception as e:
        logging.error(f"Report scheduling failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/reports/schedule/{schedule_id}")
async def remove_scheduled_report(
    schedule_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Remove a scheduled report"""
    try:
        app.state.report_scheduler.remove_schedule(schedule_id)

        # Also remove from reporting engine
        if schedule_id in app.state.reporting_engine.schedules:
            del app.state.reporting_engine.schedules[schedule_id]

        return {"status": "removed", "schedule_id": schedule_id}

    except Exception as e:
        logging.error(f"Failed to remove scheduled report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =========================================================================
# Natural Language Command Processing
# =========================================================================


class NLPCommandRequest(BaseModel):
    """Request for natural language command"""

    command: str = Field(
        ..., description="Natural language command to parse and execute"
    )
    investigation_id: Optional[str] = Field(
        None, description="Optional investigation ID to link execution"
    )
    execute: bool = Field(
        False, description="Whether to execute the command or just parse it"
    )


@app.post("/api/nlp/parse")
async def parse_nlp_command(
    request: NLPCommandRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=20, window_seconds=60)),
):
    """Parse natural language command and return execution plan"""
    try:
        from core.nlp_command_parser import NLPCommandParser

        parser = NLPCommandParser()
        parsed = parser.parse(request.command)

        return {
            "intent": parsed.intent.value,
            "target_type": parsed.target_type.value,
            "target": parsed.target,
            "modules": parsed.modules,
            "parameters": parsed.parameters,
            "confidence": parsed.confidence,
            "raw_command": parsed.raw_command,
        }

    except Exception as e:
        logging.error(f"NLP parsing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/nlp/execute")
async def execute_nlp_command(
    request: NLPCommandRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Parse and execute natural language command"""
    try:
        from core.nlp_command_parser import NLPCommandParser

        parser = NLPCommandParser()
        parsed = parser.parse(request.command)

        if parsed.confidence < 0.5:
            return {
                "status": "low_confidence",
                "message": f"Command confidence is low ({parsed.confidence:.2f}). Please rephrase.",
                "parsed": {
                    "intent": parsed.intent.value,
                    "target_type": parsed.target_type.value,
                    "target": parsed.target,
                },
            }

        # Execute the modules
        results = {}
        for module_name in parsed.modules:
            try:
                module_instance = get_module(module_name)
                if not module_instance:
                    results[module_name] = {"error": "Module not found"}
                    continue

                # Execute based on module capabilities
                if hasattr(module_instance, "search"):
                    result = module_instance.search(target=parsed.target)
                elif hasattr(module_instance, "analyze"):
                    result = module_instance.analyze(target=parsed.target)
                else:
                    result = {"message": "Module executed but no standard method found"}

                results[module_name] = result

            except Exception as e:
                logging.error(f"Module {module_name} execution failed: {e}")
                results[module_name] = {"error": str(e)}

        return {
            "status": "executed",
            "command": request.command,
            "parsed": {
                "intent": parsed.intent.value,
                "target_type": parsed.target_type.value,
                "target": parsed.target,
                "modules": parsed.modules,
                "confidence": parsed.confidence,
            },
            "results": results,
            "investigation_id": request.investigation_id,
        }

    except Exception as e:
        logging.error(f"NLP execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/nlp/examples")
async def get_nlp_examples():
    """Get example natural language commands"""
    try:
        from core.nlp_command_parser import NLPCommandParser

        parser = NLPCommandParser()
        examples = parser.get_example_commands()

        return {"examples": examples, "count": len(examples)}

    except Exception as e:
        logging.error(f"Failed to get NLP examples: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =========================================================================
# Chat History Management
# =========================================================================


class ChatMessageRequest(BaseModel):
    """Request to add chat message"""

    conversation_id: str = Field(..., description="Conversation ID")
    role: str = Field(..., description="Message role (user or assistant)")
    content: str = Field(..., description="Message content")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Optional metadata")


class CreateConversationRequest(BaseModel):
    """Request to create conversation"""

    investigation_id: Optional[str] = Field(
        None, description="Optional investigation ID"
    )
    title: str = Field("New Conversation", description="Conversation title")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Optional metadata")


@app.post("/api/chat/conversations")
async def create_chat_conversation(
    request: CreateConversationRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=50, window_seconds=3600)),
):
    """Create a new chat conversation"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        conversation_id = manager.create_conversation(
            investigation_id=request.investigation_id,
            title=request.title,
            metadata=request.metadata or {},
        )

        return {
            "conversation_id": conversation_id,
            "investigation_id": request.investigation_id,
            "title": request.title,
            "created_at": datetime.now().isoformat(),
        }

    except Exception as e:
        logging.error(f"Failed to create conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat/messages")
async def add_chat_message(
    request: ChatMessageRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=100, window_seconds=3600)),
):
    """Add a message to a conversation"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        message_id = manager.add_message(
            conversation_id=request.conversation_id,
            role=request.role,
            content=request.content,
            metadata=request.metadata or {},
        )

        return {
            "message_id": message_id,
            "conversation_id": request.conversation_id,
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as e:
        logging.error(f"Failed to add message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/conversations/{conversation_id}")
async def get_chat_conversation(
    conversation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Get a conversation with all messages"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        conversation = manager.get_conversation(conversation_id)

        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")

        return {
            "id": conversation.id,
            "investigation_id": conversation.investigation_id,
            "title": conversation.title,
            "created_at": conversation.created_at,
            "updated_at": conversation.updated_at,
            "messages": [
                {
                    "id": msg.id,
                    "role": msg.role,
                    "content": msg.content,
                    "timestamp": msg.timestamp,
                    "metadata": msg.metadata,
                }
                for msg in conversation.messages
            ],
            "metadata": conversation.metadata,
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to get conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/conversations")
async def list_chat_conversations(
    investigation_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    user_id: Optional[str] = Depends(verify_token),
):
    """List all conversations"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        conversations = manager.list_conversations(
            investigation_id=investigation_id, limit=limit, offset=offset
        )

        return {"conversations": conversations, "count": len(conversations)}

    except Exception as e:
        logging.error(f"Failed to list conversations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/chat/conversations/{conversation_id}")
async def delete_chat_conversation(
    conversation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Delete a conversation"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        deleted = manager.delete_conversation(conversation_id)

        if not deleted:
            raise HTTPException(status_code=404, detail="Conversation not found")

        return {"status": "deleted", "conversation_id": conversation_id}

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to delete conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/search")
async def search_chat_messages(
    query: str, limit: int = 50, user_id: Optional[str] = Depends(verify_token)
):
    """Search messages by content"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        results = manager.search_messages(query=query, limit=limit)

        return {"results": results, "count": len(results), "query": query}

    except Exception as e:
        logging.error(f"Failed to search messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/stats")
async def get_chat_stats(user_id: Optional[str] = Depends(verify_token)):
    """Get chat history statistics"""
    try:
        from core.chat_history_manager import ChatHistoryManager

        manager = ChatHistoryManager()
        stats = manager.get_stats()

        return stats

    except Exception as e:
        logging.error(f"Failed to get chat stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/conversations/{conversation_id}/export")
async def export_chat_conversation(
    conversation_id: str,
    format: str = "json",
    user_id: Optional[str] = Depends(verify_token),
):
    """Export a conversation to file"""
    try:
        from core.chat_history_manager import ChatHistoryManager
        from fastapi.responses import FileResponse

        manager = ChatHistoryManager()
        filepath = manager.export_conversation(conversation_id, format=format)

        if not filepath:
            raise HTTPException(status_code=404, detail="Conversation not found")

        return FileResponse(path=filepath, filename=os.path.basename(filepath))

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to export conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/scheduled")
async def get_scheduled_reports(user_id: Optional[str] = Depends(verify_token)):
    """Get list of scheduled reports"""
    try:
        schedules = app.state.report_scheduler.get_active_schedules()

        return {"schedules": schedules}

    except Exception as e:
        logging.error(f"Failed to get scheduled reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reports/process-scheduled")
async def process_scheduled_reports():
    """Process all due scheduled reports (internal endpoint)"""
    try:
        processed = await app.state.report_scheduler.execute_all_due_reports()

        return {
            "processed_schedules": processed,
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as e:
        logging.error(f"Failed to process scheduled reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/stats")
async def get_graph_statistics(user_id: Optional[str] = Depends(verify_token)):
    """Get graph database statistics"""
    try:
        stats = await app.state.graph_db.get_graph_statistics()
        return stats

    except Exception as e:
        logging.error(f"Failed to get graph statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/graph/entities")
async def create_graph_entity(
    entity_data: Dict[str, Any],
    user_id: Optional[str] = Depends(rate_limit(limit=50, window_seconds=300)),
):
    """Create an entity in the graph database"""
    try:
        from database.graph_database import Entity

        entity = Entity(
            id=entity_data["id"],
            type=entity_data["type"],
            name=entity_data["name"],
            properties=entity_data.get("properties", {}),
            labels=set(entity_data.get("labels", [])),
        )

        success = await app.state.graph_db.create_entity(entity)

        return {"success": success, "entity_id": entity.id}

    except Exception as e:
        logging.error(f"Failed to create graph entity: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/graph/relationships")
async def create_graph_relationship(
    relationship_data: Dict[str, Any],
    user_id: Optional[str] = Depends(rate_limit(limit=50, window_seconds=300)),
):
    """Create a relationship in the graph database"""
    try:
        from database.graph_database import Relationship

        relationship = Relationship(
            source_id=relationship_data["source_id"],
            target_id=relationship_data["target_id"],
            type=relationship_data["type"],
            properties=relationship_data.get("properties", {}),
            confidence=relationship_data.get("confidence", 1.0),
            source=relationship_data.get("source", ""),
        )

        success = await app.state.graph_db.create_relationship(relationship)

        return {"success": success, "relationship_type": relationship.type}

    except Exception as e:
        logging.error(f"Failed to create graph relationship: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/entities/{entity_id}/related")
async def get_related_entities(
    entity_id: str,
    relationship_type: Optional[str] = None,
    max_depth: int = 2,
    user_id: Optional[str] = Depends(verify_token),
):
    """Get entities related to the specified entity"""
    try:
        related = await app.state.graph_db.find_related_entities(
            entity_id, relationship_type, max_depth
        )

        return {
            "entity_id": entity_id,
            "related_entities": related,
            "total_found": len(related),
        }

    except Exception as e:
        logging.error(f"Failed to get related entities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/entities/search")
async def search_entities(
    name: str,
    entity_type: Optional[str] = None,
    user_id: Optional[str] = Depends(verify_token),
):
    """Search for entities by name"""
    try:
        entity = await app.state.graph_db.find_entity_by_name(name, entity_type)

        if entity:
            return {
                "found": True,
                "entity": {
                    "id": entity.id,
                    "type": entity.type,
                    "name": entity.name,
                    "properties": entity.properties,
                    "labels": list(entity.labels),
                    "created_at": entity.created_at.isoformat(),
                    "updated_at": entity.updated_at.isoformat(),
                },
            }
        else:
            return {"found": False}

    except Exception as e:
        logging.error(f"Failed to search entities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/path")
async def find_entity_path(
    source_id: str, target_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Find the shortest path between two entities"""
    try:
        path = await app.state.graph_db.find_shortest_path(source_id, target_id)

        return {
            "source_id": source_id,
            "target_id": target_id,
            "path_found": path is not None,
            "path": path,
        }

    except Exception as e:
        logging.error(f"Failed to find entity path: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/communities")
async def detect_communities(user_id: Optional[str] = Depends(verify_token)):
    """Detect communities/clusters in the graph"""
    try:
        communities = await app.state.graph_db.detect_communities()

        return {"communities": communities, "total_communities": len(communities)}

    except Exception as e:
        logging.error(f"Failed to detect communities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/centrality")
async def calculate_centrality(
    entity_type: Optional[str] = None, user_id: Optional[str] = Depends(verify_token)
):
    """Calculate centrality measures for entities"""
    try:
        centrality = await app.state.graph_db.calculate_centrality(entity_type)

        return {
            "centrality_scores": centrality,
            "entity_type_filter": entity_type,
            "total_entities": len(centrality),
        }

    except Exception as e:
        logging.error(f"Failed to calculate centrality: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/graph/import")
async def import_investigation_to_graph(
    investigation_id: str,
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Import investigation data into the graph database"""
    try:
        # Get investigation data
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=investigation_id, owner_id=user_id
        )

        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Import to graph database
        import_result = await app.state.graph_db.import_investigation_data(
            investigation
        )

        return {
            "investigation_id": investigation_id,
            "import_result": import_result,
            "status": "completed",
        }

    except Exception as e:
        logging.error(f"Failed to import investigation to graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/export")
async def export_graph_data(
    format: str = "json", user_id: Optional[str] = Depends(verify_token)
):
    """Export graph data for external analysis"""
    try:
        export_data = await app.state.graph_db.export_graph_data(format)

        if export_data:
            return {
                "export_format": format,
                "data": export_data,
                "exported_at": datetime.now().isoformat(),
            }
        else:
            raise HTTPException(status_code=500, detail="Export failed")

    except Exception as e:
        logging.error(f"Failed to export graph data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Real-Time Intelligence Feeds API Endpoints
# ============================================================================


@app.get("/api/feeds/status")
async def get_feeds_status(user_id: Optional[str] = Depends(verify_token)):
    """Get the current status of all intelligence feeds"""
    try:
        status = await app.state.intelligence_feeds.get_feed_status()
        return {
            "feeds": status,
            "timestamp": datetime.now().isoformat(),
            "active_feeds": len([f for f in status.values() if f.get("active", False)]),
        }
    except Exception as e:
        logging.error(f"Failed to get feeds status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/{feed_name}/enable")
async def enable_feed(
    feed_name: str,
    user_id: Optional[str] = Depends(rate_limit(limit=5, window_seconds=300)),
):
    """Enable a specific intelligence feed"""
    try:
        success = await app.state.intelligence_feeds.enable_feed(feed_name)
        if success:
            return {"feed_name": feed_name, "status": "enabled"}
        else:
            raise HTTPException(
                status_code=400, detail=f"Failed to enable feed: {feed_name}"
            )
    except Exception as e:
        logging.error(f"Failed to enable feed {feed_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/{feed_name}/disable")
async def disable_feed(
    feed_name: str,
    user_id: Optional[str] = Depends(rate_limit(limit=5, window_seconds=300)),
):
    """Disable a specific intelligence feed"""
    try:
        success = await app.state.intelligence_feeds.disable_feed(feed_name)
        if success:
            return {"feed_name": feed_name, "status": "disabled"}
        else:
            raise HTTPException(
                status_code=400, detail=f"Failed to disable feed: {feed_name}"
            )
    except Exception as e:
        logging.error(f"Failed to disable feed {feed_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/feeds/alerts")
async def get_recent_alerts(
    limit: int = 50, user_id: Optional[str] = Depends(verify_token)
):
    """Get recent intelligence alerts"""
    try:
        alerts = await app.state.intelligence_feeds.get_recent_alerts(limit)
        return {
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logging.error(f"Failed to get recent alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Acknowledge an intelligence alert"""
    try:
        success = await app.state.intelligence_feeds.acknowledge_alert(
            alert_id, user_id
        )
        if success:
            return {"alert_id": alert_id, "status": "acknowledged"}
        else:
            raise HTTPException(status_code=404, detail="Alert not found")
    except Exception as e:
        logging.error(f"Failed to acknowledge alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/subscribe")
async def subscribe_to_alerts(
    alert_types: List[str],
    notification_channels: Optional[List[str]] = None,
    user_id: Optional[str] = Depends(verify_token),
):
    """Subscribe to specific types of intelligence alerts"""
    try:
        if notification_channels is None:
            notification_channels = ["websocket"]
        subscription_id = await app.state.intelligence_feeds.subscribe_to_alerts(
            user_id, alert_types, notification_channels
        )
        return {
            "subscription_id": subscription_id,
            "alert_types": alert_types,
            "channels": notification_channels,
            "status": "active",
        }
    except Exception as e:
        logging.error(f"Failed to create subscription: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/feeds/subscription/{subscription_id}")
async def unsubscribe_from_alerts(
    subscription_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Unsubscribe from intelligence alerts"""
    try:
        success = await app.state.intelligence_feeds.unsubscribe_from_alerts(
            subscription_id, user_id
        )
        if success:
            return {"subscription_id": subscription_id, "status": "cancelled"}
        else:
            raise HTTPException(status_code=404, detail="Subscription not found")
    except Exception as e:
        logging.error(f"Failed to cancel subscription {subscription_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/feeds/sources")
async def get_feed_sources(user_id: Optional[str] = Depends(verify_token)):
    """Get information about available intelligence feed sources"""
    try:
        sources = await app.state.intelligence_feeds.get_feed_sources()
        return {
            "sources": sources,
            "total_sources": len(sources),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logging.error(f"Failed to get feed sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/{feed_name}/configure")
async def configure_feed_api_key(
    feed_name: str,
    config: Dict[str, Any],
    user_id: Optional[str] = Depends(rate_limit(limit=5, window_seconds=300)),
):
    """Configure API key and settings for a specific feed"""
    try:
        api_key = config.get("api_key")
        if api_key:
            success = await app.state.intelligence_feeds.configure_feed_api_key(
                feed_name, api_key
            )
            if success:
                return {"feed_name": feed_name, "status": "configured"}
            else:
                raise HTTPException(status_code=404, detail="Feed not found")
        else:
            raise HTTPException(status_code=400, detail="API key required")
    except Exception as e:
        logging.error(f"Failed to configure feed {feed_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/custom")
async def add_custom_feed(
    feed_config: Dict[str, Any],
    user_id: Optional[str] = Depends(rate_limit(limit=2, window_seconds=3600)),
):
    """Add a custom intelligence feed source"""
    try:
        from realtime.realtime_feeds import FeedSource, FeedType

        feed = FeedSource(
            name=feed_config["name"],
            feed_type=FeedType(feed_config["feed_type"]),
            url=feed_config["url"],
            api_key=feed_config.get("api_key"),
            update_interval=feed_config.get("update_interval", 300),
            headers=feed_config.get("headers", {}),
            rate_limit=feed_config.get("rate_limit", 10),
            enabled=feed_config.get("enabled", True),
        )

        success = await app.state.intelligence_feeds.add_custom_feed(feed)
        if success:
            return {
                "feed_name": feed.name,
                "status": "added",
                "timestamp": datetime.now().isoformat(),
            }
        else:
            raise HTTPException(status_code=409, detail="Feed already exists")
    except Exception as e:
        logging.error(f"Failed to add custom feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/feeds/{feed_name}")
async def remove_feed(
    feed_name: str,
    user_id: Optional[str] = Depends(rate_limit(limit=2, window_seconds=3600)),
):
    """Remove an intelligence feed source"""
    try:
        success = await app.state.intelligence_feeds.remove_feed(feed_name)
        if success:
            return {
                "feed_name": feed_name,
                "status": "removed",
                "timestamp": datetime.now().isoformat(),
            }
        else:
            raise HTTPException(status_code=404, detail="Feed not found")
    except Exception as e:
        logging.error(f"Failed to remove feed {feed_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/{feed_name}/test")
async def test_feed_connection(
    feed_name: str,
    user_id: Optional[str] = Depends(rate_limit(limit=3, window_seconds=300)),
):
    """Test connection to a specific intelligence feed"""
    try:
        test_result = await app.state.intelligence_feeds.test_feed_connection(feed_name)
        return {
            "feed_name": feed_name,
            "connection_test": test_result,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logging.error(f"Failed to test feed connection {feed_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Demo Utilities (Unsafe for production - behind dev auth token only)
# ============================================================================


@app.post("/api/investigations/{investigation_id}/demo/seed-tasks")
async def seed_demo_tasks(
    investigation_id: str, user_id: Optional[str] = Depends(verify_token)
):
    """Seed synthetic tasks for demo UI when advanced manager is not active.

    Returns list of synthetic tasks. If advanced manager present, instructs
    user to rely on real tasks instead.
    """
    try:
        result = await app.state.investigation_manager.seed_demo_tasks(
            investigation_id=investigation_id, owner_id=user_id
        )
        return result
    except ValueError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except Exception as e:  # pragma: no cover
        logging.error(f"Demo seeding failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to seed demo tasks")


# ============================================================================
# Security Framework API Endpoints
# ============================================================================

# Import and setup security API routes

setup_security_routes(app)  # type: ignore


# ============================================================================
# WebSocket Endpoints
# ============================================================================


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time updates"""
    await app.state.ws_manager.connect(websocket, client_id)

    try:
        while True:
            data = await websocket.receive_json()

            # Handle subscription to investigation updates
            if data.get("type") == "subscribe_investigation":
                investigation_id = data.get("investigation_id")
                if investigation_id:
                    await app.state.ws_manager.subscribe_to_investigation(
                        client_id, investigation_id
                    )
                    await websocket.send_json(
                        {
                            "type": "subscription_confirmed",
                            "investigation_id": investigation_id,
                        }
                    )

    except WebSocketDisconnect:
        app.state.ws_manager.disconnect(client_id)
    except Exception as e:
        logging.error(f"WebSocket error: {e}")
        app.state.ws_manager.disconnect(client_id)


@app.websocket("/ws/alerts/{user_id}")
async def alerts_websocket_endpoint(websocket: WebSocket, user_id: str):
    """WebSocket endpoint for real-time intelligence alerts"""
    await websocket.accept()

    subscription_id = None
    try:
        # Subscribe to alerts for this user
        subscription_id = await app.state.intelligence_feeds.subscribe_to_alerts(
            user_id, ["all"], ["websocket"]
        )

        # Send initial connection confirmation
        await websocket.send_json(
            {
                "type": "connection_established",
                "user_id": user_id,
                "subscription_id": subscription_id,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Keep connection alive and listen for client messages
        while True:
            try:
                # Wait for client messages (with timeout)
                data = await websocket.receive_json()

                # Handle client commands
                if data.get("type") == "ping":
                    await websocket.send_json(
                        {"type": "pong", "timestamp": datetime.now().isoformat()}
                    )
                elif data.get("type") == "unsubscribe":
                    await app.state.intelligence_feeds.unsubscribe_from_alerts(
                        subscription_id, user_id
                    )
                    await websocket.send_json(
                        {"type": "unsubscribed", "subscription_id": subscription_id}
                    )
                    break

            except Exception:
                # If no message received within timeout, continue listening
                continue

    except WebSocketDisconnect:
        # Clean up subscription on disconnect
        try:
            if subscription_id:
                await app.state.intelligence_feeds.unsubscribe_from_alerts(
                    subscription_id, user_id
                )
        except Exception:
            pass
    except Exception as e:
        logging.error(f"Alerts WebSocket error for user {user_id}: {e}")


# ============================================================================
# Error Handlers
# ============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now().isoformat(),
        },
    )


# =========================================================================
# Autopivoting and Autonomous Investigations
# =========================================================================


class AutopivotRequest(BaseModel):
    """Request for autopivot suggestions"""

    investigation_id: str = Field(..., description="Investigation ID to analyze")
    max_pivots: int = Field(5, description="Maximum number of pivot suggestions")


class AutonomousInvestigationRequest(BaseModel):
    """Request for autonomous investigation"""

    target: str = Field(..., description="Initial investigation target")
    target_type: str = Field(
        ..., description="Type of target (domain, email, ip, etc.)"
    )
    max_depth: int = Field(3, description="Maximum pivot depth")
    max_pivots_per_level: int = Field(3, description="Maximum pivots per level")


@app.post("/api/autopivot/suggest")
async def suggest_autopivots(
    request: AutopivotRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Get AI-powered pivot suggestions for an investigation"""
    try:
        # Get investigation data
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=request.investigation_id, owner_id=user_id
        )

        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Get autopivot suggestions from AI engine
        pivots = await app.state.ai_engine.suggest_autopivots(
            investigation_data=investigation, max_pivots=request.max_pivots
        )

        return {
            "investigation_id": request.investigation_id,
            "pivot_suggestions": pivots,
            "count": len(pivots),
            "generated_at": datetime.now().isoformat(),
        }

    except Exception as e:
        logging.error(f"Autopivot suggestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/autopivot/autonomous")
async def start_autonomous_investigation(
    request: AutonomousInvestigationRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=5, window_seconds=3600)),
):
    """Start fully autonomous investigation with automatic pivoting"""
    try:
        # Execute autonomous investigation
        result = await app.state.ai_engine.execute_autonomous_investigation(
            initial_target=request.target,
            target_type=request.target_type,
            max_depth=request.max_depth,
            max_pivots_per_level=request.max_pivots_per_level,
        )

        return {
            "status": "completed",
            "investigation_tree": result,
            "total_targets": result["total_targets_investigated"],
            "total_pivots": result["total_pivots"],
            "depth_reached": len(result["levels"]),
            "started_at": result["started_at"],
            "completed_at": result["completed_at"],
        }

    except Exception as e:
        logging.error(f"Autonomous investigation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =========================================================================
# Enhanced Offline LLM and Investigation Tracking
# =========================================================================


class EnhancedAnalysisRequest(BaseModel):
    """Request for enhanced offline LLM analysis"""

    investigation_id: str = Field(..., description="Investigation ID to analyze")
    focus: str = Field(
        "comprehensive",
        description="Analysis focus (comprehensive, threats, connections, timeline)",
    )


class InvestigationFindingRequest(BaseModel):
    """Request to add finding to investigation"""

    investigation_id: str = Field(..., description="Investigation ID")
    finding_type: str = Field(
        ..., description="Type of finding (email, domain, ip, etc.)"
    )
    value: str = Field(..., description="Finding value")
    source_module: str = Field(..., description="Source module")
    confidence: float = Field(0.8, description="Confidence score (0-1)")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class DetailedReportRequest(BaseModel):
    """Request for user-friendly detailed report"""

    investigation_id: str = Field(..., description="Investigation ID")
    include_analysis: bool = Field(True, description="Include AI analysis")
    include_leads: bool = Field(True, description="Include investigation leads")


@app.post("/api/enhanced/analyze")
async def enhanced_offline_analysis(
    request: EnhancedAnalysisRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=5, window_seconds=300)),
):
    """
    Get enhanced offline LLM analysis using local models (no API key required).
    Provides detailed, user-friendly breakdown of findings.
    """
    try:
        from core.offline_llm_engine import get_offline_llm_engine
        from core.investigation_tracker import get_investigation_tracker

        # Get investigation data
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=request.investigation_id, owner_id=user_id
        )

        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Get offline LLM engine
        llm_engine = get_offline_llm_engine()

        # Perform analysis
        analysis = llm_engine.analyze_investigation_data(
            investigation_data=investigation, focus=request.focus
        )

        # Get investigation tracker for findings
        tracker = get_investigation_tracker()
        findings = tracker.get_all_findings(request.investigation_id)

        return {
            "investigation_id": request.investigation_id,
            "analysis": {
                "summary": analysis.summary,
                "key_findings": analysis.key_findings,
                "recommended_actions": analysis.recommended_actions,
                "confidence": analysis.confidence,
                "entities_found": analysis.entities_found,
                "risk_assessment": analysis.risk_assessment,
                "investigation_leads": analysis.investigation_leads,
            },
            "total_tracked_findings": len(findings),
            "generated_at": analysis.timestamp.isoformat(),
            "model_used": "Offline LLM (Phi-3/TinyLlama)",
        }

    except Exception as e:
        logging.error(f"Enhanced analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigation/tracking/create")
async def create_investigation_tracking(
    investigation_id: str,
    name: str,
    user_id: Optional[str] = Depends(verify_token),
):
    """Create investigation tracking for persistent findings storage"""
    try:
        from core.investigation_tracker import get_investigation_tracker

        tracker = get_investigation_tracker()
        success = tracker.create_investigation(investigation_id, name)

        if success:
            return {
                "investigation_id": investigation_id,
                "name": name,
                "status": "created",
                "message": "Investigation tracking created successfully",
            }
        else:
            return {
                "investigation_id": investigation_id,
                "status": "exists",
                "message": "Investigation tracking already exists",
            }

    except Exception as e:
        logging.error(f"Failed to create investigation tracking: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigation/tracking/finding")
async def add_investigation_finding(
    request: InvestigationFindingRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=100, window_seconds=3600)),
):
    """Add a finding to investigation tracking (builds progressively without data loss)"""
    try:
        from core.investigation_tracker import get_investigation_tracker

        tracker = get_investigation_tracker()
        finding_id = tracker.add_finding(
            investigation_id=request.investigation_id,
            finding_type=request.finding_type,
            value=request.value,
            source_module=request.source_module,
            confidence=request.confidence,
            metadata=request.metadata,
        )

        if finding_id:
            return {
                "finding_id": finding_id,
                "status": "added",
                "message": "Finding added to investigation",
            }
        else:
            return {
                "status": "duplicate",
                "message": "Finding already exists in investigation",
            }

    except Exception as e:
        logging.error(f"Failed to add finding: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigation/tracking/{investigation_id}/findings")
async def get_investigation_findings(
    investigation_id: str,
    finding_type: Optional[str] = None,
    user_id: Optional[str] = Depends(verify_token),
):
    """Get all findings for an investigation"""
    try:
        from core.investigation_tracker import get_investigation_tracker

        tracker = get_investigation_tracker()
        findings = tracker.get_all_findings(investigation_id, finding_type=finding_type)

        return {
            "investigation_id": investigation_id,
            "total_findings": len(findings),
            "findings": [
                {
                    "id": f.id,
                    "type": f.finding_type,
                    "value": f.value,
                    "source": f.source_module,
                    "discovered_at": f.discovered_at,
                    "confidence": f.confidence,
                    "status": f.follow_up_status,
                    "notes": f.notes,
                }
                for f in findings
            ],
        }

    except Exception as e:
        logging.error(f"Failed to get findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigation/tracking/{investigation_id}/leads")
async def get_investigation_leads(
    investigation_id: str,
    status: Optional[str] = None,
    user_id: Optional[str] = Depends(verify_token),
):
    """Get all investigation leads with explanations"""
    try:
        from core.investigation_tracker import get_investigation_tracker

        tracker = get_investigation_tracker()
        leads = tracker.get_all_leads(investigation_id, status=status)

        return {
            "investigation_id": investigation_id,
            "total_leads": len(leads),
            "leads": [
                {
                    "id": lead.id,
                    "target": lead.target,
                    "type": lead.target_type,
                    "reason": lead.reason,
                    "priority": lead.priority,
                    "suggested_modules": lead.suggested_modules,
                    "status": lead.status,
                    "findings_count": lead.findings_count,
                    "estimated_value": lead.estimated_value,
                }
                for lead in leads
            ],
        }

    except Exception as e:
        logging.error(f"Failed to get leads: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigation/tracking/{investigation_id}/summary")
async def get_investigation_summary(
    investigation_id: str,
    user_id: Optional[str] = Depends(verify_token),
):
    """Get comprehensive investigation summary"""
    try:
        from core.investigation_tracker import get_investigation_tracker

        tracker = get_investigation_tracker()
        summary = tracker.get_investigation_summary(investigation_id)

        return summary

    except Exception as e:
        logging.error(f"Failed to get summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reports/user-friendly")
async def generate_user_friendly_report(
    request: DetailedReportRequest,
    user_id: Optional[str] = Depends(rate_limit(limit=10, window_seconds=3600)),
):
    """
    Generate comprehensive user-friendly report with detailed breakdowns.
    Includes: What We Know, What We Think, What We Can Find, Why It Matters
    """
    try:
        from core.enhanced_reporting import EnhancedReportGenerator
        from core.investigation_tracker import get_investigation_tracker
        from core.offline_llm_engine import get_offline_llm_engine

        # Get investigation data
        investigation = await app.state.investigation_manager.get_investigation(
            investigation_id=request.investigation_id, owner_id=user_id
        )

        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Get tracked findings and leads
        tracker = get_investigation_tracker()
        findings = tracker.get_all_findings(request.investigation_id)
        leads = tracker.get_all_leads(request.investigation_id)

        # Convert to dict format
        findings_dict = [
            {
                "finding_type": f.finding_type,
                "value": f.value,
                "source_module": f.source_module,
                "confidence": f.confidence,
                "discovered_at": f.discovered_at,
                "metadata": f.metadata,
            }
            for f in findings
        ]

        leads_dict = [
            {
                "target": lead.target,
                "target_type": lead.target_type,
                "reason": lead.reason,
                "priority": lead.priority,
                "suggested_modules": lead.suggested_modules,
                "status": lead.status,
                "estimated_value": lead.estimated_value,
            }
            for lead in leads
        ]

        # Get AI analysis if requested
        analysis = None
        if request.include_analysis:
            llm_engine = get_offline_llm_engine()
            analysis_result = llm_engine.analyze_investigation_data(investigation)
            analysis = {
                "summary": analysis_result.summary,
                "confidence": analysis_result.confidence,
            }

        # Generate report
        report_generator = EnhancedReportGenerator()
        report = report_generator.generate_user_friendly_report(
            investigation_data=investigation,
            findings=findings_dict,
            leads=leads_dict if request.include_leads else [],
            analysis=analysis,
        )

        return report

    except Exception as e:
        logging.error(f"Failed to generate user-friendly report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigation/tracking/{investigation_id}/export")
async def export_investigation_data(
    investigation_id: str,
    format: str = "json",
    user_id: Optional[str] = Depends(verify_token),
):
    """Export complete investigation data (json or markdown)"""
    try:
        from core.investigation_tracker import get_investigation_tracker
        from fastapi.responses import FileResponse

        tracker = get_investigation_tracker()
        filepath = tracker.export_investigation(investigation_id, format=format)

        if filepath:
            return FileResponse(
                path=filepath,
                filename=os.path.basename(filepath),
                media_type="application/json" if format == "json" else "text/markdown",
            )
        else:
            raise HTTPException(status_code=404, detail="Investigation not found")

    except Exception as e:
        logging.error(f"Failed to export investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logging.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.now().isoformat(),
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api_server:app", host="0.0.0.0", port=8000, reload=True, log_level="info"
    )
