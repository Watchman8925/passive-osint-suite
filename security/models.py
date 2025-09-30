"""
Security Models
Data models for the security framework
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Permission(Enum):
    """System permissions"""

    # Intelligence access
    READ_INTELLIGENCE = "read:intelligence"
    WRITE_INTELLIGENCE = "write:intelligence"
    DELETE_INTELLIGENCE = "delete:intelligence"

    # User management
    MANAGE_USERS = "manage:users"
    MANAGE_ROLES = "manage:roles"

    # Data classification
    VIEW_SENSITIVE = "view:sensitive"
    VIEW_CONFIDENTIAL = "view:confidential"
    VIEW_RESTRICTED = "view:restricted"

    # System administration
    SYSTEM_ADMIN = "system:admin"
    AUDIT_LOGS = "audit:logs"


class DataClassification(Enum):
    """Data classification levels"""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class DataCategory(Enum):
    """Data categories for classification"""

    PERSONAL = "personal"
    FINANCIAL = "financial"
    INTELLIGENCE = "intelligence"
    TECHNICAL = "technical"
    OPERATIONAL = "operational"


@dataclass
class DataObject:
    """Represents a classified data object"""

    id: str
    name: str
    classification: str
    category: str
    owner_id: str
    created_at: datetime
    last_modified: datetime
    tags: List[str]
    metadata: Dict[str, Any]
    access_log: List[Dict] = field(default_factory=list)
    retention_policy: str = "standard"  # standard, extended, permanent

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        data["last_modified"] = self.last_modified.isoformat()
        return data


@dataclass
class AccessPolicy:
    """Access policy for data objects"""

    id: str
    name: str
    classification_level: str
    required_permissions: List[str]
    required_clearance: str
    allowed_roles: List[str]
    denied_users: List[str]
    time_restrictions: Dict[str, Any]  # time-based access rules
    location_restrictions: List[str]  # IP/location restrictions
    created_at: datetime

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        return data


@dataclass
class User:
    """User account with security clearance"""

    id: str
    username: str
    email: str
    full_name: str
    roles: List[str]
    permissions: List[str]
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    password_hash: Optional[str] = None
    api_keys: Optional[List[str]] = None
    security_clearance: str = "standard"

    def __post_init__(self):
        if self.api_keys is None:
            self.api_keys = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        if self.last_login:
            data["last_login"] = self.last_login.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create from dictionary"""
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("last_login"):
            data["last_login"] = datetime.fromisoformat(data["last_login"])
        return cls(**data)


@dataclass
class SecurityEvent:
    """Security event for monitoring"""

    id: str
    timestamp: datetime
    event_type: str
    severity: str  # low, medium, high, critical
    user_id: Optional[str]
    ip_address: str
    user_agent: str
    details: Dict[str, Any]
    source: str  # system component that generated the event

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class SecurityAlert:
    """Security alert for immediate attention"""

    id: str
    timestamp: datetime
    alert_type: str
    severity: str
    description: str
    affected_users: List[str]
    affected_data: List[str]
    recommended_actions: List[str]
    status: str  # new, acknowledged, resolved
    assigned_to: Optional[str] = None
    resolved_at: Optional[datetime] = None
    notes: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        if self.resolved_at:
            data["resolved_at"] = self.resolved_at.isoformat()
        return data


@dataclass
class Session:
    """User session with expiration"""

    session_id: str
    user_id: str
    ip_address: str
    user_agent: str
    created_at: datetime
    expires_at: datetime
    is_active: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Create from dictionary"""
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        return cls(**data)
