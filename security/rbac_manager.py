"""
Role-Based Access Control (RBAC) System
Comprehensive security framework for OSINT suite
"""

import json
import logging
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import bcrypt

from .security_database import security_db


class Permission(Enum):
    """System permissions"""

    # Intelligence access
    READ_INTELLIGENCE = "read:intelligence"
    WRITE_INTELLIGENCE = "write:intelligence"
    DELETE_INTELLIGENCE = "delete:intelligence"

    # User management
    MANAGE_USERS = "manage:users"
    MANAGE_ROLES = "manage:roles"

    # System administration
    SYSTEM_ADMIN = "admin:system"
    AUDIT_VIEW = "view:audit"

    # API access
    API_ACCESS = "access:api"
    API_ADMIN = "admin:api"

    # Data classification
    VIEW_SENSITIVE = "view:sensitive"
    VIEW_CONFIDENTIAL = "view:confidential"
    VIEW_RESTRICTED = "view:restricted"

    # Export capabilities
    EXPORT_DATA = "export:data"
    EXPORT_REPORTS = "export:reports"


class Role(Enum):
    """System roles with predefined permissions"""

    GUEST = "guest"
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    INVESTIGATOR = "investigator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


@dataclass
class User:
    """User account information"""

    id: str
    username: str
    email: str
    full_name: str
    roles: List[str]
    permissions: Set[str]
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    password_hash: Optional[str] = None
    api_keys: List[str] = None
    security_clearance: str = (
        "standard"  # standard, sensitive, confidential, restricted
    )

    def __post_init__(self):
        if self.api_keys is None:
            self.api_keys = []

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        if self.last_login:
            data["last_login"] = self.last_login.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "User":
        """Create from dictionary"""
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("last_login"):
            data["last_login"] = datetime.fromisoformat(data["last_login"])
        return cls(**data)


@dataclass
class Session:
    """User session information"""

    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    is_active: bool = True


class RBACManager:
    """Role-Based Access Control Manager"""

    def __init__(self, config_path: str = "security/rbac_config.json"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)

        # JWT configuration
        self.jwt_secret = secrets.token_hex(32)
        self.jwt_algorithm = "HS256"
        self.session_timeout = timedelta(hours=8)

        # Role-permission mappings
        self.role_permissions = self._initialize_role_permissions()

        # User and session storage
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.audit_log: List[Dict] = []

        # Load configuration
        self.load_config()

    def _initialize_role_permissions(self) -> Dict[str, Set[str]]:
        """Initialize default role-permission mappings"""
        return {
            Role.GUEST.value: {
                Permission.READ_INTELLIGENCE.value,
                Permission.API_ACCESS.value,
            },
            Role.ANALYST.value: {
                Permission.READ_INTELLIGENCE.value,
                Permission.WRITE_INTELLIGENCE.value,
                Permission.API_ACCESS.value,
                Permission.EXPORT_REPORTS.value,
                Permission.VIEW_SENSITIVE.value,
            },
            Role.SENIOR_ANALYST.value: {
                Permission.READ_INTELLIGENCE.value,
                Permission.WRITE_INTELLIGENCE.value,
                Permission.DELETE_INTELLIGENCE.value,
                Permission.API_ACCESS.value,
                Permission.EXPORT_DATA.value,
                Permission.EXPORT_REPORTS.value,
                Permission.VIEW_SENSITIVE.value,
                Permission.VIEW_CONFIDENTIAL.value,
            },
            Role.INVESTIGATOR.value: {
                Permission.READ_INTELLIGENCE.value,
                Permission.WRITE_INTELLIGENCE.value,
                Permission.DELETE_INTELLIGENCE.value,
                Permission.API_ACCESS.value,
                Permission.EXPORT_DATA.value,
                Permission.EXPORT_REPORTS.value,
                Permission.VIEW_SENSITIVE.value,
                Permission.VIEW_CONFIDENTIAL.value,
                Permission.VIEW_RESTRICTED.value,
                Permission.AUDIT_VIEW.value,
            },
            Role.ADMIN.value: {
                Permission.READ_INTELLIGENCE.value,
                Permission.WRITE_INTELLIGENCE.value,
                Permission.DELETE_INTELLIGENCE.value,
                Permission.MANAGE_USERS.value,
                Permission.MANAGE_ROLES.value,
                Permission.API_ACCESS.value,
                Permission.API_ADMIN.value,
                Permission.EXPORT_DATA.value,
                Permission.EXPORT_REPORTS.value,
                Permission.VIEW_SENSITIVE.value,
                Permission.VIEW_CONFIDENTIAL.value,
                Permission.VIEW_RESTRICTED.value,
                Permission.AUDIT_VIEW.value,
            },
            Role.SUPER_ADMIN.value: {
                Permission.SYSTEM_ADMIN.value,
                Permission.READ_INTELLIGENCE.value,
                Permission.WRITE_INTELLIGENCE.value,
                Permission.DELETE_INTELLIGENCE.value,
                Permission.MANAGE_USERS.value,
                Permission.MANAGE_ROLES.value,
                Permission.API_ACCESS.value,
                Permission.API_ADMIN.value,
                Permission.EXPORT_DATA.value,
                Permission.EXPORT_REPORTS.value,
                Permission.VIEW_SENSITIVE.value,
                Permission.VIEW_CONFIDENTIAL.value,
                Permission.VIEW_RESTRICTED.value,
                Permission.AUDIT_VIEW.value,
            },
        }

    def create_user(
        self,
        username: str,
        password: str,
        email: str,
        full_name: str,
        role: str = "analyst",
    ) -> User:
        """Create a new user with the specified role"""
        if not self._validate_password(password):
            raise ValueError("Password does not meet security requirements")

        user_id = f"user_{secrets.token_hex(8)}"
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        user = User(
            id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            roles=[role],
            permissions=list(self.role_permissions.get(role, set())),
            is_active=True,
            created_at=datetime.now(),
            last_login=None,
            password_hash=password_hash,
        )

        # Save to database
        if security_db.save_user(user):
            self.logger.info(f"User created: {username} ({user_id})")
            return user
        else:
            raise Exception("Failed to create user in database")

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password"""
        user = security_db.load_user_by_username(username)
        if not user or not user.is_active:
            return None

        if user.password_hash and bcrypt.checkpw(
            password.encode(), user.password_hash.encode()
        ):
            # Update last login
            user.last_login = datetime.now()
            security_db.save_user(user)
            return user

        return None

    def create_session(self, user: User, ip_address: str, user_agent: str) -> Session:
        """Create a new user session"""
        session_id = secrets.token_hex(32)
        expires_at = datetime.now() + self.session_timeout

        session = Session(
            session_id=session_id,
            user_id=user.id,
            created_at=datetime.now(),
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True,
        )

        # Save to database
        security_db.save_session(session)
        self._audit_log("session_created", user.id, {"session_id": session_id})

        return session

    def validate_session(self, session_id: str) -> Optional[User]:
        """Validate session and return user if valid"""
        session = security_db.load_session(session_id)
        if not session or not session.is_active:
            return None

        if datetime.now() > session.expires_at:
            session.is_active = False
            security_db.save_session(session)
            self._audit_log(
                "session_expired", session.user_id, {"session_id": session_id}
            )
            return None

        user = security_db.load_user(session.user_id)
        if not user or not user.is_active:
            return None

        return user

    def invalidate_session(self, session_id: str):
        """Invalidate a user session"""
        session = security_db.load_session(session_id)
        if session:
            session.is_active = False
            security_db.save_session(session)
            self._audit_log(
                "session_invalidated", session.user_id, {"session_id": session_id}
            )

    def check_permission(self, user: User, permission: str) -> bool:
        """Check if user has specific permission"""
        return permission in user.permissions

    def check_role(self, user: User, role: str) -> bool:
        """Check if user has specific role"""
        return role in user.roles

    def require_permission(self, permission: str) -> Callable:
        """Decorator to require specific permission"""

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract user from request context (implementation depends on framework)
                user = self._get_current_user()
                if not user:
                    raise PermissionError("Authentication required")

                if not self.check_permission(user, permission):
                    self._audit_log(
                        "permission_denied",
                        user.id,
                        {"permission": permission, "function": func.__name__},
                    )
                    raise PermissionError(f"Permission denied: {permission}")

                self._audit_log(
                    "permission_granted",
                    user.id,
                    {"permission": permission, "function": func.__name__},
                )
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def require_role(self, role: str) -> Callable:
        """Decorator to require specific role"""

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                user = self._get_current_user()
                if not user:
                    raise PermissionError("Authentication required")

                if not self.check_role(user, role):
                    self._audit_log(
                        "role_denied",
                        user.id,
                        {"role": role, "function": func.__name__},
                    )
                    raise PermissionError(f"Role required: {role}")

                return func(*args, **kwargs)

            return wrapper

        return decorator

    def add_role_to_user(self, user_id: str, role: str):
        """Add role to user and update permissions"""
        user = self.users.get(user_id)
        if not user:
            raise ValueError(f"User not found: {user_id}")

        if role not in self.role_permissions:
            raise ValueError(f"Invalid role: {role}")

        if role not in user.roles:
            user.roles.append(role)
            user.permissions.update(self.role_permissions[role])
            self._audit_log("role_added", user_id, {"role": role})

    def remove_role_from_user(self, user_id: str, role: str):
        """Remove role from user and update permissions"""
        user = self.users.get(user_id)
        if not user:
            raise ValueError(f"User not found: {user_id}")

        if role in user.roles:
            user.roles.remove(role)
            # Recalculate permissions from remaining roles
            user.permissions = set()
            for r in user.roles:
                user.permissions.update(self.role_permissions[r])
            self._audit_log("role_removed", user_id, {"role": role})

    def create_api_key(self, user_id: str, name: str, expires_days: int = 365) -> str:
        """Create API key for user"""
        user = self.users.get(user_id)
        if not user:
            raise ValueError(f"User not found: {user_id}")

        api_key = secrets.token_hex(32)

        # Store API key with metadata

        # In a real implementation, this would be stored in a database
        user.api_keys.append(api_key)

        self._audit_log(
            "api_key_created", user_id, {"name": name, "expires_days": expires_days}
        )
        return api_key

    def validate_api_key(self, api_key: str) -> Optional[User]:
        """Validate API key and return user"""
        for user in self.users.values():
            if api_key in user.api_keys and user.is_active:
                self._audit_log("api_key_used", user.id, {"key_name": "api_key"})
                return user
        return None

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Get audit log entries with optional filtering"""
        log_entries = self.audit_log

        if user_id:
            log_entries = [
                entry for entry in log_entries if entry["user_id"] == user_id
            ]

        if action:
            log_entries = [entry for entry in log_entries if entry["action"] == action]

        return log_entries[-limit:]

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

    def _find_user_by_username(self, username: str) -> Optional[User]:
        """Find user by username"""
        return security_db.load_user_by_username(username)

    def _get_current_user(self) -> Optional[User]:
        """Get current user from request context (framework-specific)"""
        # This would be implemented based on the web framework being used
        # For now, return None (would need to be overridden)
        return None

    def _audit_log(self, action: str, user_id: str, details: Dict = None):
        """Log security event"""
        if details is None:
            details = {}

        log_entry = {
            "timestamp": datetime.now(),
            "action": action,
            "user_id": user_id,
            "details": details,
            "ip_address": getattr(self, "_current_ip", "unknown"),
        }

        self.audit_log.append(log_entry)

        # Keep only last 10,000 entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]

    def save_config(self):
        """Save RBAC configuration to file"""
        try:
            config = {
                "jwt_secret": self.jwt_secret,
                "role_permissions": {
                    role: list(perms) for role, perms in self.role_permissions.items()
                },
                "users": {
                    user_id: user.to_dict() for user_id, user in self.users.items()
                },
                "audit_log": self.audit_log[-1000:],  # Keep last 1000 entries
            }

            self.config_path.parent.mkdir(exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2, default=str)

            self.logger.info(f"RBAC configuration saved to {self.config_path}")

        except Exception as e:
            self.logger.error(f"Error saving RBAC config: {e}")

    def load_config(self):
        """Load RBAC configuration from file"""
        try:
            if not self.config_path.exists():
                self.logger.info("RBAC config file not found, using defaults")
                return

            with open(self.config_path, "r") as f:
                config = json.load(f)

            # Load role permissions
            self.role_permissions = {
                role: set(perms)
                for role, perms in config.get("role_permissions", {}).items()
            }

            # Load users
            self.users = {}
            for user_id, user_data in config.get("users", {}).items():
                self.users[user_id] = User.from_dict(user_data)

            # Load audit log
            self.audit_log = config.get("audit_log", [])

            self.logger.info(f"RBAC configuration loaded from {self.config_path}")

        except Exception as e:
            self.logger.error(f"Error loading RBAC config: {e}")


# Global RBAC manager instance
rbac_manager = RBACManager()


# Convenience functions
def require_permission(permission: str):
    """Convenience decorator for requiring permissions"""
    return rbac_manager.require_permission(permission)


def require_role(role: str):
    """Convenience decorator for requiring roles"""
    return rbac_manager.require_role(role)


def check_permission(user: User, permission: str) -> bool:
    """Check if user has permission"""
    return rbac_manager.check_permission(user, permission)


def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user"""
    return rbac_manager.authenticate_user(username, password)
