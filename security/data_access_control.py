"""
Data Classification and Access Control
Security framework for protecting sensitive intelligence data
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .models import (AccessPolicy, DataCategory, DataClassification,
                     DataObject, Permission, User)

# from .rbac_manager import rbac_manager  # Circular import - will be injected later


class DataAccessControl:
    """Data classification and access control system"""

    def __init__(self, config_path: str = "security/data_access_config.json"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)

        # Database connection (initialized later)
        self.db = None

        # Data objects registry
        self.data_objects: Dict[str, DataObject] = {}

        # Classification mappings
        self.classification_permissions = {
            DataClassification.PUBLIC.value: set(),
            DataClassification.INTERNAL.value: {Permission.READ_INTELLIGENCE.value},
            DataClassification.SENSITIVE.value: {Permission.VIEW_SENSITIVE.value},
            DataClassification.CONFIDENTIAL.value: {Permission.VIEW_CONFIDENTIAL.value},
            DataClassification.RESTRICTED.value: {Permission.VIEW_RESTRICTED.value},
        }

        # Security clearance levels
        self.clearance_levels = {
            "standard": 1,
            "sensitive": 2,
            "confidential": 3,
            "restricted": 4,
        }

        # Load configuration
        self.load_config()

    def set_database(self, db_connection):
        """Set the database connection for persistence"""
        self.db = db_connection

    def classify_data(
        self,
        data_id: str,
        name: str,
        classification: str,
        category: str,
        owner_id: str,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ) -> DataObject:
        """Classify a data object"""
        if classification not in [c.value for c in DataClassification]:
            raise ValueError(f"Invalid classification: {classification}")

        if category not in [c.value for c in DataCategory]:
            raise ValueError(f"Invalid category: {category}")

        if tags is None:
            tags = []
        if metadata is None:
            metadata = {}

        data_object = DataObject(
            id=data_id,
            name=name,
            classification=classification,
            category=category,
            owner_id=owner_id,
            created_at=datetime.now(),
            last_modified=datetime.now(),
            tags=tags,
            metadata=metadata,
        )

        # Save to database
        if self.db:
            self.db.save_data_object(data_object)

        self._audit_access(
            "data_classified",
            owner_id,
            data_id,
            {"classification": classification, "category": category},
        )

        self.logger.info(f"Data classified: {data_id} as {classification}")
        return data_object

    def check_access(
        self, user: User, data_id: str, action: str = "read", context: Optional[Dict] = None
    ) -> bool:
        """Check if user has access to data object"""
        if context is None:
            context = {}

        # Load data object from database
        data_object = self.db.load_data_object(data_id) if self.db else None
        if not data_object:
            self._audit_access(
                "access_denied",
                user.id,
                data_id,
                {"reason": "data_not_found", "action": action},
            )
            return False

        # Check basic classification permissions
        required_perms = self.classification_permissions[data_object.classification]
        if required_perms and not any(
            perm in user.permissions for perm in required_perms
        ):
            self._audit_access(
                "access_denied",
                user.id,
                data_id,
                {"reason": "insufficient_permissions", "action": action},
            )
            return False

        # Check security clearance
        user_clearance_level = self.clearance_levels.get(user.security_clearance, 0)
        data_clearance_level = self.clearance_levels.get(data_object.classification, 0)

        if user_clearance_level < data_clearance_level:
            self._audit_access(
                "access_denied",
                user.id,
                data_id,
                {"reason": "insufficient_clearance", "action": action},
            )
            return False

        # Check custom access policies
        if not self._check_access_policies(user, data_object, action, context):
            return False

        # Log successful access
        self._audit_access(
            "access_granted",
            user.id,
            data_id,
            {"action": action, "classification": data_object.classification},
        )

        return True

    def _check_access_policies(
        self, user: User, data_object: DataObject, action: str, context: Dict
    ) -> bool:
        """Check custom access policies"""
        # Check if user is owner (owners have full access)
        if user.id == data_object.owner_id:
            return True

        # Load access policies from database
        if self.db:
            policies: List[AccessPolicy] = self.db.load_access_policies(
                resource_type="data", resource_id=data_object.id
            )
        else:
            policies = []

        # Check role-based policies
        for policy in policies:
            if policy.classification_level == data_object.classification:
                # Check denied users
                if user.id in policy.denied_users:
                    self._audit_access(
                        "access_denied",
                        user.id,
                        data_object.id,
                        {"reason": "user_denied", "policy": policy.id},
                    )
                    return False

                # Check allowed roles
                if policy.allowed_roles and not any(
                    role in user.roles for role in policy.allowed_roles
                ):
                    continue

                # Check required permissions
                if not all(
                    perm in user.permissions for perm in policy.required_permissions
                ):
                    continue

                # Check clearance
                if self.clearance_levels.get(
                    user.security_clearance, 0
                ) < self.clearance_levels.get(policy.required_clearance, 0):
                    continue

                # Check time restrictions
                if not self._check_time_restrictions(policy, context):
                    continue

                # Check location restrictions
                if not self._check_location_restrictions(policy, context):
                    continue

                return True

        return False

    def _check_time_restrictions(self, policy: AccessPolicy, context: Dict) -> bool:
        """Check time-based access restrictions"""
        if not policy.time_restrictions:
            return True

        now = datetime.now()
        current_time = now.time()
        current_day = now.weekday()

        # Check allowed hours
        if "allowed_hours" in policy.time_restrictions:
            start_hour, end_hour = policy.time_restrictions["allowed_hours"]
            if not (start_hour <= current_time.hour <= end_hour):
                return False

        # Check allowed days
        if "allowed_days" in policy.time_restrictions:
            if current_day not in policy.time_restrictions["allowed_days"]:
                return False

        return True

    def _check_location_restrictions(self, policy: AccessPolicy, context: Dict) -> bool:
        """Check location-based access restrictions"""
        if not policy.location_restrictions:
            return True

        user_ip = context.get("ip_address", "")
        user_location = context.get("location", "")

        # Check IP restrictions
        for restriction in policy.location_restrictions:
            if restriction.startswith("ip:"):
                allowed_ip = restriction[3:]
                if user_ip.startswith(allowed_ip):
                    return True
            elif restriction.startswith("country:"):
                allowed_country = restriction[8:]
                if user_location == allowed_country:
                    return True

        return False

    def create_access_policy(
        self,
        name: str,
        classification_level: str,
        required_permissions: Optional[List[str]] = None,
        required_clearance: str = "standard",
        allowed_roles: Optional[List[str]] = None,
        denied_users: Optional[List[str]] = None,
        time_restrictions: Optional[Dict] = None,
        location_restrictions: Optional[List[str]] = None,
    ) -> AccessPolicy:
        """Create a custom access policy"""
        if required_permissions is None:
            required_permissions = []
        if allowed_roles is None:
            allowed_roles = []
        if denied_users is None:
            denied_users = []
        if time_restrictions is None:
            time_restrictions = {}
        if location_restrictions is None:
            location_restrictions = []

        policy_id = f"policy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        policy = AccessPolicy(
            id=policy_id,
            name=name,
            classification_level=classification_level,
            required_permissions=required_permissions,
            required_clearance=required_clearance,
            allowed_roles=allowed_roles,
            denied_users=denied_users,
            time_restrictions=time_restrictions,
            location_restrictions=location_restrictions,
            created_at=datetime.now(),
        )

        # Save to database
        if self.db:
            self.db.save_access_policy(policy)

        self.logger.info(f"Access policy created: {policy_id}")

        return policy

    def get_data_access_log(self, data_id: str, limit: int = 100) -> List[Dict]:
        """Get access log for a data object"""
        data_object = self.data_objects.get(data_id)
        if not data_object:
            return []

        return data_object.access_log[-limit:]

    def get_user_access_log(self, user_id: str, limit: int = 100) -> List[Dict]:
        """Get access log for a user across all data objects"""
        user_log = []

        for data_object in self.data_objects.values():
            for log_entry in data_object.access_log:
                if log_entry.get("user_id") == user_id:
                    user_log.append(
                        {
                            **log_entry,
                            "data_id": data_object.id,
                            "data_name": data_object.name,
                        }
                    )

        # Sort by timestamp
        user_log.sort(key=lambda x: x["timestamp"], reverse=True)
        return user_log[:limit]

    def apply_data_retention(self):
        """Apply data retention policies"""
        now = datetime.now()
        deleted_count = 0

        for data_id, data_object in list(self.data_objects.items()):
            if data_object.retention_policy == "standard":
                # Delete after 1 year
                if (now - data_object.created_at).days > 365:
                    del self.data_objects[data_id]
                    deleted_count += 1
            elif data_object.retention_policy == "extended":
                # Delete after 5 years
                if (now - data_object.created_at).days > 1825:
                    del self.data_objects[data_id]
                    deleted_count += 1
            # permanent policy = never delete

        if deleted_count > 0:
            self.logger.info(f"Applied data retention: {deleted_count} objects deleted")

    def _audit_access(
        self, action: str, user_id: str, data_id: str, details: Optional[Dict] = None
    ):
        """Log access event"""
        if details is None:
            details = {}

        log_entry = {
            "timestamp": datetime.now(),
            "action": action,
            "user_id": user_id,
            "data_id": data_id,
            "details": details,
            "ip_address": getattr(self, "_current_ip", "unknown"),
        }

        # Add to data object's access log
        data_object = self.data_objects.get(data_id)
        if data_object:
            data_object.access_log.append(log_entry)

            # Keep only last 1000 entries per object
            if len(data_object.access_log) > 1000:
                data_object.access_log = data_object.access_log[-1000:]

    def save_config(self):
        """Save data access configuration"""
        try:
            config = {
                "data_objects": {
                    obj_id: obj.to_dict() for obj_id, obj in self.data_objects.items()
                },
                "access_policies": {
                    pol_id: pol.to_dict()
                    for pol_id, pol in self.access_policies.items()
                },
            }

            self.config_path.parent.mkdir(exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2, default=str)

            self.logger.info(f"Data access config saved to {self.config_path}")

        except Exception as e:
            self.logger.error(f"Error saving data access config: {e}")

    def load_config(self):
        """Load data access configuration"""
        try:
            if not self.config_path.exists():
                self.logger.info("Data access config file not found, using defaults")
                return

            with open(self.config_path, "r") as f:
                config = json.load(f)

            # Load data objects
            self.data_objects = {}
            for obj_id, obj_data in config.get("data_objects", {}).items():
                # Convert timestamps
                obj_data["created_at"] = datetime.fromisoformat(obj_data["created_at"])
                obj_data["last_modified"] = datetime.fromisoformat(
                    obj_data["last_modified"]
                )
                self.data_objects[obj_id] = DataObject(**obj_data)

            # Load access policies
            self.access_policies = {}
            for pol_id, pol_data in config.get("access_policies", {}).items():
                pol_data["created_at"] = datetime.fromisoformat(pol_data["created_at"])
                self.access_policies[pol_id] = AccessPolicy(**pol_data)

            self.logger.info(f"Data access config loaded from {self.config_path}")

        except Exception as e:
            self.logger.error(f"Error loading data access config: {e}")


# Global data access control instance
data_access_control = DataAccessControl()


# Convenience functions
def classify_data(
    data_id: str, name: str, classification: str, category: str, owner_id: str, **kwargs
) -> DataObject:
    """Classify data object"""
    return data_access_control.classify_data(
        data_id, name, classification, category, owner_id, **kwargs
    )


def check_data_access(
    user: User, data_id: str, action: str = "read", **context
) -> bool:
    """Check data access"""
    return data_access_control.check_access(user, data_id, action, context)


def require_data_access(data_id: str, action: str = "read") -> Callable:
    """Decorator to require data access"""

    def decorator(func: Callable) -> Callable:
        def wrapper(user, *args, **kwargs):
            if not user:
                raise PermissionError("Authentication required")

            if not data_access_control.check_access(user, data_id, action):
                raise PermissionError(f"Access denied to data: {data_id}")

            return func(user, *args, **kwargs)

        return wrapper

    return decorator
