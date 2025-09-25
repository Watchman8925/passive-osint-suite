"""
Security API Integration
FastAPI security middleware and protected endpoints
"""

import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from .rbac_manager import User, rbac_manager
from .security_monitor import log_security_event, security_monitor

# Security configuration
JWT_SECRET = "your-jwt-secret-key-change-in-production"  # Should be from environment
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# API key configuration
API_KEY_HEADER = "X-API-Key"
API_KEY_EXPIRATION_DAYS = 365


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for request monitoring and protection"""

    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.logger = logging.getLogger(__name__)

    async def dispatch(self, request: Request, call_next):
        """Process each request through security checks"""
        start_time = datetime.now()

        # Extract client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "unknown")
        api_key = request.headers.get(API_KEY_HEADER)

        # Log API access
        log_security_event(
            "api_access",
            severity="low",
            ip_address=client_ip,
            user_agent=user_agent,
            details={
                "method": request.method,
                "path": str(request.url.path),
                "api_key_provided": api_key is not None,
            },
            source="api_middleware",
        )

        try:
            # Process the request
            response = await call_next(request)

            # Log successful response
            processing_time = (datetime.now() - start_time).total_seconds()
            log_security_event(
                "api_response",
                severity="low",
                ip_address=client_ip,
                user_agent=user_agent,
                details={
                    "status_code": response.status_code,
                    "processing_time": processing_time,
                },
                source="api_middleware",
            )

            return response

        except Exception as e:
            # Log error response
            log_security_event(
                "api_error",
                severity="medium",
                ip_address=client_ip,
                user_agent=user_agent,
                details={"error_type": type(e).__name__, "error_message": str(e)},
                source="api_middleware",
            )
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Check for real IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct connection
        return request.client.host if request.client else "unknown"


class LoginRequest(BaseModel):
    """Login request model"""

    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    """Login response model"""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class UserCreateRequest(BaseModel):
    """User creation request model"""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    full_name: str = Field(..., min_length=1, max_length=100)
    role: str = "user"


class UserUpdateRequest(BaseModel):
    """User update request model"""

    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class PermissionRequest(BaseModel):
    """Permission request model"""

    resource: str
    action: str
    context: Optional[Dict[str, Any]] = None


class APIKeyCreateRequest(BaseModel):
    """API key creation request model"""

    name: str = Field(..., min_length=1, max_length=50)
    permissions: List[str] = Field(default_factory=list)
    expires_in_days: Optional[int] = API_KEY_EXPIRATION_DAYS


class APIKeyResponse(BaseModel):
    """API key response model"""

    key_id: str
    name: str
    created_at: datetime
    expires_at: Optional[datetime]
    permissions: List[str]
    is_active: bool


class SecurityController:
    """Security API controller"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_scheme = HTTPBearer(auto_error=False)

    def create_access_token(self, user: User) -> str:
        """Create JWT access token"""
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        to_encode = {
            "sub": user.id,
            "username": user.username,
            "role": user.role,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
        }
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None

    def get_current_user(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Optional[User]:
        """Get current authenticated user"""
        if not credentials:
            return None

        payload = self.verify_token(credentials.credentials)
        if not payload:
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        return rbac_manager.get_user(user_id)

    def require_authentication(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ):
        """Require authentication for endpoint"""
        user = self.get_current_user(credentials)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing authentication token",
            )
        return user

    def require_permission(self, resource: str, action: str):
        """Create permission requirement decorator"""

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract user from kwargs (added by FastAPI dependency injection)
                user = kwargs.get("current_user")
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required",
                    )

                # Check permission
                if not rbac_manager.check_permission(user.id, resource, action):
                    log_security_event(
                        "access_denied",
                        severity="medium",
                        user_id=user.id,
                        details={
                            "resource": resource,
                            "action": action,
                            "reason": "insufficient_permissions",
                        },
                        source="api_permission_check",
                    )

                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Insufficient permissions for {resource}:{action}",
                    )

                return await func(*args, **kwargs)

            return wrapper

        return decorator

    def check_api_key(self, request: Request) -> Optional[Dict[str, Any]]:
        """Check API key authentication"""
        api_key = request.headers.get(API_KEY_HEADER)
        if not api_key:
            return None

        # Verify API key (this would be implemented in rbac_manager)
        return rbac_manager.verify_api_key(api_key)

    def create_api_key(
        self,
        name: str,
        user_id: str,
        permissions: List[str] = None,
        expires_in_days: int = None,
    ) -> Dict[str, Any]:
        """Create API key for user"""
        if permissions is None:
            permissions = []

        if expires_in_days is None:
            expires_in_days = API_KEY_EXPIRATION_DAYS

        # Generate secure API key
        key_value = secrets.token_urlsafe(32)
        key_id = f"key_{secrets.token_hex(8)}"

        expires_at = (
            datetime.now() + timedelta(days=expires_in_days)
            if expires_in_days
            else None
        )

        api_key_data = {
            "key_id": key_id,
            "key_value": key_value,
            "name": name,
            "user_id": user_id,
            "permissions": permissions,
            "created_at": datetime.now(),
            "expires_at": expires_at,
            "is_active": True,
        }

        # Store API key (would be implemented in rbac_manager)
        rbac_manager.store_api_key(api_key_data)

        return {
            "key_id": key_id,
            "key_value": key_value,
            "name": name,
            "permissions": permissions,
            "expires_at": expires_at,
        }


# Global security controller instance
security_controller = SecurityController()


def setup_security_routes(app: FastAPI):
    """Setup security-related API routes"""

    @app.post("/auth/login", response_model=LoginResponse)
    async def login(request: LoginRequest, req: Request):
        """Authenticate user and return access token"""
        client_ip = security_controller._get_client_ip(req)
        user_agent = req.headers.get("User-Agent", "unknown")

        try:
            user = rbac_manager.authenticate_user(request.username, request.password)

            if not user:
                log_security_event(
                    "authentication_failed",
                    severity="medium",
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details={
                        "username": request.username,
                        "reason": "invalid_credentials",
                    },
                    source="login_endpoint",
                )

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                )

            # Update last login
            rbac_manager.update_last_login(user.id)

            # Create access token
            access_token = security_controller.create_access_token(user)

            log_security_event(
                "authentication_success",
                severity="low",
                user_id=user.id,
                ip_address=client_ip,
                user_agent=user_agent,
                details={"username": request.username},
                source="login_endpoint",
            )

            return LoginResponse(
                access_token=access_token,
                expires_in=JWT_EXPIRATION_HOURS * 3600,
                user={
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "is_active": user.is_active,
                },
            )

        except Exception as e:
            log_security_event(
                "authentication_error",
                severity="high",
                ip_address=client_ip,
                user_agent=user_agent,
                details={"username": request.username, "error": str(e)},
                source="login_endpoint",
            )
            raise

    @app.post("/auth/logout")
    async def logout(
        current_user: User = Depends(security_controller.require_authentication),
    ):
        """Logout user and invalidate session"""
        rbac_manager.invalidate_user_sessions(current_user.id)

        log_security_event(
            "logout",
            severity="low",
            user_id=current_user.id,
            details={"username": current_user.username},
            source="logout_endpoint",
        )

        return {"message": "Logged out successfully"}

    @app.get("/auth/me")
    async def get_current_user_info(
        current_user: User = Depends(security_controller.require_authentication),
    ):
        """Get current user information"""
        return {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "role": current_user.role,
            "is_active": current_user.is_active,
            "last_login": (
                current_user.last_login.isoformat() if current_user.last_login else None
            ),
            "created_at": current_user.created_at.isoformat(),
        }

    @app.post(
        "/users", dependencies=[Depends(security_controller.require_authentication)]
    )
    @security_controller.require_permission("users", "create")
    async def create_user(request: UserCreateRequest, current_user: User):
        """Create new user"""
        try:
            # Check if user already exists
            if rbac_manager.get_user_by_username(request.username):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists",
                )

            # Create user
            user = rbac_manager.create_user(
                username=request.username,
                password=request.password,
                email=request.email,
                full_name=request.full_name,
                role=request.role,
            )

            log_security_event(
                "user_created",
                severity="medium",
                user_id=current_user.id,
                details={
                    "created_user_id": user.id,
                    "created_username": request.username,
                    "role": request.role,
                },
                source="user_management",
            )

            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
            }

        except Exception as e:
            log_security_event(
                "user_creation_failed",
                severity="high",
                user_id=current_user.id,
                details={"username": request.username, "error": str(e)},
                source="user_management",
            )
            raise

    @app.get("/users")
    @security_controller.require_permission("users", "read")
    async def list_users(current_user: User, skip: int = 0, limit: int = 50):
        """List users"""
        users = rbac_manager.list_users(skip=skip, limit=limit)
        return {
            "users": [
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "is_active": user.is_active,
                    "last_login": (
                        user.last_login.isoformat() if user.last_login else None
                    ),
                    "created_at": user.created_at.isoformat(),
                }
                for user in users
            ],
            "total": len(rbac_manager.users),
        }

    @app.put("/users/{user_id}")
    @security_controller.require_permission("users", "update")
    async def update_user(user_id: str, request: UserUpdateRequest, current_user: User):
        """Update user"""
        user = rbac_manager.get_user(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        # Update user
        updates = request.dict(exclude_unset=True)
        rbac_manager.update_user(user_id, **updates)

        log_security_event(
            "user_updated",
            severity="medium",
            user_id=current_user.id,
            details={"updated_user_id": user_id, "updates": list(updates.keys())},
            source="user_management",
        )

        return {"message": "User updated successfully"}

    @app.delete("/users/{user_id}")
    @security_controller.require_permission("users", "delete")
    async def delete_user(user_id: str, current_user: User):
        """Delete user"""
        user = rbac_manager.get_user(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        rbac_manager.delete_user(user_id)

        log_security_event(
            "user_deleted",
            severity="high",
            user_id=current_user.id,
            details={"deleted_user_id": user_id, "deleted_username": user.username},
            source="user_management",
        )

        return {"message": "User deleted successfully"}

    @app.post("/auth/api-keys", response_model=APIKeyResponse)
    async def create_api_key(
        request: APIKeyCreateRequest,
        current_user: User = Depends(security_controller.require_authentication),
    ):
        """Create API key"""
        api_key_data = security_controller.create_api_key(
            name=request.name,
            user_id=current_user.id,
            permissions=request.permissions,
            expires_in_days=request.expires_in_days,
        )

        log_security_event(
            "api_key_created",
            severity="medium",
            user_id=current_user.id,
            details={
                "key_id": api_key_data["key_id"],
                "name": request.name,
                "permissions": request.permissions,
            },
            source="api_key_management",
        )

        return APIKeyResponse(
            key_id=api_key_data["key_id"],
            name=request.name,
            created_at=datetime.now(),
            expires_at=api_key_data["expires_at"],
            permissions=request.permissions,
            is_active=True,
        )

    @app.get("/auth/api-keys")
    async def list_api_keys(
        current_user: User = Depends(security_controller.require_authentication),
    ):
        """List user's API keys"""
        # This would be implemented in rbac_manager
        api_keys = rbac_manager.get_user_api_keys(current_user.id)

        return {
            "api_keys": [
                {
                    "key_id": key["key_id"],
                    "name": key["name"],
                    "created_at": key["created_at"].isoformat(),
                    "expires_at": (
                        key["expires_at"].isoformat() if key["expires_at"] else None
                    ),
                    "permissions": key["permissions"],
                    "is_active": key["is_active"],
                }
                for key in api_keys
            ]
        }

    @app.delete("/auth/api-keys/{key_id}")
    async def revoke_api_key(
        key_id: str,
        current_user: User = Depends(security_controller.require_authentication),
    ):
        """Revoke API key"""
        rbac_manager.revoke_api_key(key_id, current_user.id)

        log_security_event(
            "api_key_revoked",
            severity="medium",
            user_id=current_user.id,
            details={"key_id": key_id},
            source="api_key_management",
        )

        return {"message": "API key revoked successfully"}

    @app.get("/security/report")
    @security_controller.require_permission("security", "read")
    async def get_security_report(current_user: User, days: int = 7):
        """Get security report"""
        report = security_monitor.get_security_report(days)
        return report

    @app.get("/security/compliance")
    @security_controller.require_permission("security", "read")
    async def get_compliance_report(current_user: User):
        """Get compliance report"""
        report = security_monitor.get_compliance_report()
        return report

    @app.get("/security/alerts")
    @security_controller.require_permission("security", "read")
    async def get_security_alerts(
        current_user: User, status_filter: Optional[str] = None
    ):
        """Get security alerts"""
        alerts = security_monitor.security_alerts

        if status_filter:
            alerts = [a for a in alerts if a.status == status_filter]

        return {
            "alerts": [
                {
                    "id": alert.id,
                    "timestamp": alert.timestamp.isoformat(),
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "description": alert.description,
                    "affected_users": alert.affected_users,
                    "affected_data": alert.affected_data,
                    "recommended_actions": alert.recommended_actions,
                    "status": alert.status,
                    "assigned_to": alert.assigned_to,
                }
                for alert in alerts[-50:]
            ]  # Last 50 alerts
        }


def init_security_middleware(app: FastAPI):
    """Initialize security middleware"""
    app.add_middleware(SecurityMiddleware)

    # Setup security routes
    setup_security_routes(app)

    # Start security monitoring
    security_monitor.start_monitoring()

    return app
