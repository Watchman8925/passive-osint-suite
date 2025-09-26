#!/usr/bin/env python3
"""
Advanced OSINT Suite API Server
FastAPI-based backend with AI integration, real-time WebSocket support,
and comprehensive investigation management.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Literal, cast

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
    import redis  # type: ignore
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
import importlib
import importlib.util
from typing import Callable as _Callable, Any as _Any

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
        JSONResponse = lambda content=None, status_code=200: {"status_code": status_code, "content": content}  # type: ignore
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

    def JSONResponse(content=None, status_code=200):
        return {"status_code": status_code, "content": content}

    class FileResponse:  # type: ignore
        def __init__(self, *a, **k):
            pass
from core.ai_engine import OSINTAIEngine
# Core OSINT modules
from security.audit_trail import audit_trail
from capabilities import REGISTRY as CAPABILITY_REGISTRY
from execution.engine import ExecutionEngine, compute_investigation_provenance
from investigations.investigation_adapter import PersistentInvestigationStore
from security.opsec_policy import enforce_policy
from planner import Planner
from utils.transport import ProxiedTransport, get_tor_status
from utils.rate_limiter import RateLimiter

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
    init_security_middleware,
    security_controller,
    setup_security_routes,
)
from security.security_monitor import security_monitor

# Use imported items to avoid unused import warnings
_ = CATEGORIES, MODULE_REGISTRY, get_module, get_modules_by_category, RealTimeIntelligenceFeed, setup_security_routes

# ============================================================================
# Configuration and Models
# ============================================================================


class AppConfig:
    """Application configuration"""

    SECRET_KEY = os.getenv("OSINT_SECRET_KEY", "change-this-secret-key-in-production-environment")
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/osint_db")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    AI_MODEL_API_KEY = os.getenv("PERPLEXITY_API_KEY", "")
    AI_MODEL_URL = os.getenv("AI_MODEL_URL", "https://api.perplexity.ai")
    AI_MODEL_PROVIDER = os.getenv("AI_MODEL_PROVIDER", "perplexity")
    AI_MODEL_NAME = os.getenv("AI_MODEL_NAME", "llama-3.1-sonar-large-128k-online")
    CORS_ORIGINS = ["http://localhost:3000", "http://localhost:8000"]  # Added for CORS


# Ensure we have a valid base class to inherit from (handles pydantic fallback)
BaseModelBase = BaseModel

class InvestigationCreate(BaseModelBase):
    """Model for creating new investigations"""

    name: Optional[str] = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    targets: List[str] = cast(
        List[str], Field(default_factory=list, min_items=1)
    )
    investigation_type: Optional[str] = Field(
        ..., pattern="^(domain|ip|email|phone|company|person)$"
    )
    priority: Optional[str] = Field(default="medium", pattern="^(low|medium|high|critical)$")
    tags: List[str] = Field(default_factory=list)  # type: ignore[assignment]
    scheduled_start: Optional[datetime] = None
    auto_reporting: bool = True


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


# ============================================================================
# Application Setup
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logging.info("🚀 Starting OSINT Suite API Server...")

    # Initialize connections (guard against missing redis/elasticsearch)
    try:
        app.state.redis = redis.from_url(AppConfig.REDIS_URL) if redis is not None else None
    except Exception:
        app.state.redis = None

    try:
        app.state.es = AsyncElasticsearch([AppConfig.ELASTICSEARCH_URL])
    except Exception:
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
        logging.warning("PersistentInvestigationStore unavailable; investigation manager disabled")

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
        app.state.reporting_engine = EnhancedReportingEngine(ai_engine=app.state.ai_engine)
        app.state.report_scheduler = ReportScheduler(app.state.reporting_engine)
        await app.state.report_scheduler.start_scheduler()
    except Exception:
        try:
            app.state.reporting_engine = EnhancedReportingEngine(ai_engine=None)
            app.state.report_scheduler = ReportScheduler(app.state.reporting_engine)
        except Exception:
            app.state.reporting_engine = None
            app.state.report_scheduler = None
        logging.warning("Reporting engine or scheduler initialization failed or partially degraded")

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
            logging.warning("⚠️  Graph database not available - relationship mapping disabled")
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
        app.state.execution_engine = ExecutionEngine(store=app.state.investigation_manager)
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
            if getattr(app.state, "report_scheduler", None) and hasattr(app.state.report_scheduler, "stop_scheduler"):
                await app.state.report_scheduler.stop_scheduler()
        except Exception:
            logging.exception("Error stopping report scheduler")

        try:
            if getattr(app.state, "es", None) and hasattr(app.state.es, "close"):
                await app.state.es.close()
        except Exception:
            logging.exception("Error closing elasticsearch client")

        try:
            if getattr(app.state, "graph_db", None) and hasattr(app.state.graph_db, "disconnect"):
                await app.state.graph_db.disconnect()
        except Exception:
            logging.exception("Error disconnecting graph database")

        try:
            if getattr(app.state, "redis", None):
                # redis may provide close or connection_pool.close; attempt close gracefully
                close_fn = getattr(app.state.redis, "close", None) or getattr(app.state.redis, "connection_pool", None)
                try:
                    if callable(close_fn):
                        close_fn()
                    elif hasattr(app.state.redis, "connection_pool") and hasattr(app.state.redis.connection_pool, "disconnect"):
                        app.state.redis.connection_pool.disconnect()
                except Exception:
                    logging.exception("Error closing redis connection")
        except Exception:
            logging.exception("Error while cleaning up redis")

        logging.info("🛑 OSINT Suite API Server shutdown complete")


app = FastAPI(
    title="OSINT Suite API",
    description="Advanced OSINT Platform with AI Integration",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Initialize Security Framework Middleware
try:
    app = init_security_middleware(app)
except Exception:
    logging.warning("Security middleware initialization failed or skipped")

# Additional Middleware
try:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=AppConfig.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)
except Exception:
    logging.warning("Middleware registration failed or middleware unavailable")

# Security
security = HTTPBearer()

# Rate Limiter instance
_limiter = RateLimiter()

def rate_limit(limit: int, window_seconds: int):
    async def dependency(user_id: str = cast(str, Depends(verify_token))):
        # Simple rate limiting: check if user can acquire a token
        # Note: This is a basic implementation. For production, consider per-user rate limiting
        if not _limiter.acquire(1):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        return user_id
    return dependency

# ============================================================================
# Authentication & Authorization (Security Framework Integration)
# ============================================================================


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
):
    """Get current authenticated user from security framework"""
    return security_controller.get_current_user(credentials)


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


# ============================================================================
# API Routes
# ============================================================================


@app.get("/api/health")
async def health_check():
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


@app.get("/tor/status")
async def tor_status():
    """Expose Tor proxy status (no external network calls)."""
    status = get_tor_status()
    # Lightweight connectivity probe to SOCKS port
    proxy_reachable = status.get("active", False)
    status["proxy_reachable"] = proxy_reachable
    status["timestamp"] = datetime.now().isoformat()
    return status


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
    investigation_id: str, user_id: str = Depends(verify_token)
):
    """Return (build if absent) the plan for an investigation."""
    store = app.state.investigation_manager
    # Load investigation to verify ownership
    inv = await store.get_investigation(investigation_id, owner_id=user_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    # Reuse adapter helper to load or build plan
    try:
        # Adapter provides private helper; replicate minimal logic if unavailable
        from investigation_adapter import (
            PersistentInvestigationStore,
        )  # type: ignore

        if isinstance(store, PersistentInvestigationStore):
            # Access its loading helper via public method path: use _load_or_build_plan if present
            if hasattr(store, "_load_or_build_plan"):
                plan = store._load_or_build_plan(store._items[investigation_id])  # type: ignore[attr-defined]
            else:
                planner = Planner()
                plan = planner.build_plan(investigation_id, inv["investigation_type"], inv["targets"])  # type: ignore
        else:  # Fallback generic
            planner = Planner()
            plan = planner.build_plan(investigation_id, inv["investigation_type"], inv["targets"])  # type: ignore
    except Exception as e:
        logging.error(f"Failed to build/load plan: {e}")
        raise HTTPException(status_code=500, detail="Plan retrieval failed")

    # Normalize and return PlanModel
    plan_id = getattr(plan, "investigation_id", investigation_id)
    plan_tasks = getattr(plan, "tasks", [])
    if hasattr(plan_tasks, "values"):
        task_iter = cast(Any, plan_tasks).values()  # type: ignore
    else:
        task_iter = plan_tasks

    tasks_out: List[PlannedTaskModel] = []
    for t in task_iter:
        tasks_out.append(
            PlannedTaskModel(
                id=getattr(t, "id", getattr(t, "task_id", None)),
                capability_id=getattr(t, "capability_id", getattr(t, "capability", None)),
                inputs=getattr(t, "inputs", {}),
                depends_on=getattr(t, "depends_on", []),
                status=getattr(t, "status", getattr(t, "state", "unknown")),
            )
        )

    return PlanModel(investigation_id=plan_id, tasks=tasks_out)


@app.post("/api/investigations/{investigation_id}/execute/all")
async def execute_all_tasks(
    investigation_id: str, user_id: str = Depends(verify_token)
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
    investigation_id: str, user_id: str = Depends(verify_token)
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
            "to": {"icao": "EGLL", "lat": 51.4700, "lon": -0.4543, "city": "London"},
            "path": [
                [40.6413, -73.7781],
                [45.0, -50.0],  # Mid-Atlantic waypoint (approx)
                [51.4700, -0.4543],
            ],
            "status": "enroute",
        }
    ]

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "ip_points": ip_points,
        "flight_routes": flight_routes,
    }


@app.post("/api/investigations")
async def create_investigation(
    investigation: InvestigationCreate,
    user_id: str = Depends(rate_limit(limit=15, window_seconds=60)),
):
    """Create a new OSINT investigation"""
    try:
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
    user_id: str = Depends(verify_token),
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
    investigation_id: str, user_id: str = Depends(verify_token)
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
    user_id: str = Depends(rate_limit(limit=30, window_seconds=300)),
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


@app.get("/api/investigations/{investigation_id}/tasks")
async def investigation_tasks(
    investigation_id: str,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    include_meta: bool = False,
    user_id: str = Depends(verify_token),
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
        if isinstance(tasks, dict) and tasks.get("investigation_id") != investigation_id:
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
    user_id: str = Depends(rate_limit(limit=10, window_seconds=300)),
):
    """Execute an OSINT module with given parameters."""
    import time

    start_time = time.time()
    try:
        # Get the module instance
        module_instance = get_module(request.module_name)
        if module_instance is None:
            raise HTTPException(status_code=404, detail=f"Module '{request.module_name}' not found")

        # Log the operation
        audit_trail.log_operation(
            operation="module_execute",
            actor=user_id,
            target=f"module:{request.module_name}",
            metadata={"parameters": request.parameters},
        )

        # Execute the module based on its type
        result = None

        # Handle different module types and their methods
        if hasattr(module_instance, "search"):
            result = module_instance.search(**request.parameters)
        elif hasattr(module_instance, "analyze_company"):
            result = module_instance.analyze_company(**request.parameters)
        elif hasattr(module_instance, "enumerate"):
            result = module_instance.enumerate(**request.parameters)
        elif hasattr(module_instance, "scrape"):
            result = module_instance.scrape(**request.parameters)
        elif hasattr(module_instance, "fetch_snapshots"):
            result = module_instance.fetch_snapshots(**request.parameters)
        elif hasattr(module_instance, "get_history"):
            result = module_instance.get_history(**request.parameters)
        elif hasattr(module_instance, "scrape_profiles"):
            result = module_instance.scrape_profiles(**request.parameters)
        elif hasattr(module_instance, "dork"):
            result = module_instance.dork(**request.parameters)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Module '{request.module_name}' does not have a supported execution method",
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
            actor=user_id,
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
    Enabled only when ENABLE_DEV_AUTH=1 environment variable is set.
    NOT for production use.
    """
    if os.getenv("ENABLE_DEV_AUTH") != "1":
        raise HTTPException(status_code=403, detail="Dev auth disabled")
    now = datetime.utcnow()
    payload = {
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "scopes": ["investigations:read", "investigations:write"],
    }
    token = jwt.encode(payload, AppConfig.SECRET_KEY, algorithm="HS256")
    return {"token": token, "expires_in": expires_minutes * 60}


@app.post("/api/ai/analyze")
async def ai_analysis(
    request: AIAnalysisRequest,
    user_id: str = Depends(rate_limit(limit=10, window_seconds=300)),
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
    user_id: str = Depends(rate_limit(limit=5, window_seconds=300)),
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


@app.get("/api/reports/scheduled")
async def get_scheduled_reports(user_id: str = Depends(verify_token)):
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
async def get_graph_statistics(user_id: str = Depends(verify_token)):
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
    user_id: str = Depends(rate_limit(limit=50, window_seconds=300)),
):
    """Create an entity in the graph database"""
    try:
        from graph_database import Entity

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
    user_id: str = Depends(rate_limit(limit=50, window_seconds=300)),
):
    """Create a relationship in the graph database"""
    try:
        from graph_database import Relationship

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
    user_id: str = Depends(verify_token),
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
    name: str, entity_type: Optional[str] = None, user_id: str = Depends(verify_token)
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
    source_id: str, target_id: str, user_id: str = Depends(verify_token)
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
async def detect_communities(user_id: str = Depends(verify_token)):
    """Detect communities/clusters in the graph"""
    try:
        communities = await app.state.graph_db.detect_communities()

        return {"communities": communities, "total_communities": len(communities)}

    except Exception as e:
        logging.error(f"Failed to detect communities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/centrality")
async def calculate_centrality(
    entity_type: Optional[str] = None, user_id: str = Depends(verify_token)
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
    user_id: str = Depends(rate_limit(limit=10, window_seconds=300)),
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
async def export_graph_data(format: str = "json", user_id: str = Depends(verify_token)):
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
async def get_feeds_status(user_id: str = Depends(verify_token)):
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
    feed_name: str, user_id: str = Depends(rate_limit(limit=5, window_seconds=300))
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
    feed_name: str, user_id: str = Depends(rate_limit(limit=5, window_seconds=300))
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
async def get_recent_alerts(limit: int = 50, user_id: str = Depends(verify_token)):
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
async def acknowledge_alert(alert_id: str, user_id: str = Depends(verify_token)):
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
    notification_channels: List[str] = ["websocket"],
    user_id: str = Depends(verify_token),
):
    """Subscribe to specific types of intelligence alerts"""
    try:
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
    subscription_id: str, user_id: str = Depends(verify_token)
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
async def get_feed_sources(user_id: str = Depends(verify_token)):
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
    user_id: str = Depends(rate_limit(limit=5, window_seconds=300)),
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
    user_id: str = Depends(rate_limit(limit=2, window_seconds=3600)),
):
    """Add a custom intelligence feed source"""
    try:
        from realtime_feeds import FeedSource, FeedType

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
    feed_name: str, user_id: str = Depends(rate_limit(limit=2, window_seconds=3600))
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
    feed_name: str, user_id: str = Depends(rate_limit(limit=3, window_seconds=300))
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
async def seed_demo_tasks(investigation_id: str, user_id: str = Depends(verify_token)):
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

setup_security_routes(app)


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
            await app.state.intelligence_feeds.unsubscribe_from_alerts(
                subscription_id, user_id
            )
        except:
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
