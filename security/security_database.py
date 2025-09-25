"""
PostgreSQL Database Integration for Security Framework
Provides persistent storage for users, sessions, audit logs, and security data
"""

import json
import logging
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    import psycopg2.extras
    from psycopg2.pool import SimpleConnectionPool

    HAS_POSTGRESQL = True
except ImportError:
    HAS_POSTGRESQL = False

    # Create dummy classes for type hints
    class SimpleConnectionPool:
        pass


from .models import (AccessPolicy, DataObject, SecurityAlert, SecurityEvent,
                     Session, User)


class SecurityDatabase:
    """PostgreSQL database adapter for security framework"""

    def __init__(self, connection_string: str = None):
        self.logger = logging.getLogger(__name__)

        # Default connection string
        if connection_string is None:
            connection_string = (
                "postgresql://osint_user:password@localhost/osint_security"
            )

        self.connection_string = connection_string
        self.pool = None

        # Try to initialize connection pool, but don't fail if PostgreSQL is not available
        try:
            self.initialize_connection_pool()
        except Exception as e:
            self.logger.warning(f"Database connection failed, using mock mode: {e}")
            self.pool = None

    def initialize_connection_pool(self):
        """Initialize PostgreSQL connection pool"""
        try:
            self.pool = SimpleConnectionPool(
                minconn=1, maxconn=10, dsn=self.connection_string
            )
            self.logger.info("PostgreSQL connection pool initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize connection pool: {e}")
            raise

    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        if self.pool is None:
            # Mock mode - yield None and handle in calling methods
            yield None
        else:
            conn = None
            try:
                conn = self.pool.getconn()
                yield conn
            finally:
                if conn:
                    self.pool.putconn(conn)

    def initialize_schema(self):
        """Initialize database schema for security framework"""
        with self.get_connection() as conn:
            if conn is None:
                self.logger.info(
                    "Database in mock mode - skipping schema initialization"
                )
                return
            with conn.cursor() as cursor:
                # Create users table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_users (
                        id VARCHAR(255) PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        full_name VARCHAR(255) NOT NULL,
                        roles TEXT[] NOT NULL DEFAULT '{}',
                        permissions TEXT[] NOT NULL DEFAULT '{}',
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        password_hash VARCHAR(255),
                        api_keys TEXT[] DEFAULT '{}',
                        security_clearance VARCHAR(50) DEFAULT 'standard'
                    )
                """
                )

                # Create sessions table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_sessions (
                        session_id VARCHAR(255) PRIMARY KEY,
                        user_id VARCHAR(255) NOT NULL REFERENCES security_users(id) ON DELETE CASCADE,
                        ip_address VARCHAR(45) NOT NULL,
                        user_agent TEXT,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE
                    )
                """
                )

                # Create data objects table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_data_objects (
                        id VARCHAR(255) PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        classification VARCHAR(50) NOT NULL,
                        category VARCHAR(100) NOT NULL,
                        owner_id VARCHAR(255) NOT NULL REFERENCES security_users(id),
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        last_modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        tags TEXT[] DEFAULT '{}',
                        metadata JSONB DEFAULT '{}',
                        access_log JSONB DEFAULT '[]',
                        retention_policy VARCHAR(50) DEFAULT 'standard'
                    )
                """
                )

                # Create access policies table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_access_policies (
                        id SERIAL PRIMARY KEY,
                        resource_type VARCHAR(100) NOT NULL,
                        resource_id VARCHAR(255) NOT NULL,
                        user_id VARCHAR(255) REFERENCES security_users(id) ON DELETE CASCADE,
                        role VARCHAR(100),
                        permissions TEXT[] NOT NULL DEFAULT '{}',
                        conditions JSONB DEFAULT '{}',
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP
                    )
                """
                )

                # Create security events table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        id VARCHAR(255) PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        event_type VARCHAR(100) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        user_id VARCHAR(255),
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        details JSONB DEFAULT '{}',
                        source VARCHAR(100) NOT NULL
                    )
                """
                )

                # Create security alerts table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_alerts (
                        id VARCHAR(255) PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        alert_type VARCHAR(100) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        description TEXT NOT NULL,
                        affected_users TEXT[] DEFAULT '{}',
                        affected_data TEXT[] DEFAULT '{}',
                        recommended_actions TEXT[] DEFAULT '{}',
                        status VARCHAR(20) NOT NULL DEFAULT 'new',
                        assigned_to VARCHAR(255),
                        resolved_at TIMESTAMP,
                        notes TEXT
                    )
                """
                )

                # Create audit log table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_audit_log (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        user_id VARCHAR(255),
                        action VARCHAR(100) NOT NULL,
                        resource_type VARCHAR(100) NOT NULL,
                        resource_id VARCHAR(255),
                        details JSONB DEFAULT '{}',
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        success BOOLEAN NOT NULL DEFAULT TRUE,
                        error_message TEXT
                    )
                """
                )

                # Create indexes for performance
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_security_users_username ON security_users(username);
                    CREATE INDEX IF NOT EXISTS idx_security_users_email ON security_users(email);
                    CREATE INDEX IF NOT EXISTS idx_security_sessions_user_id ON security_sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_security_sessions_expires_at ON security_sessions(expires_at);
                    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
                    CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
                    CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
                    CREATE INDEX IF NOT EXISTS idx_security_audit_log_timestamp ON security_audit_log(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_security_audit_log_user_id ON security_audit_log(user_id);
                """
                )

                conn.commit()
                self.logger.info("Security database schema initialized")

    # User Management Methods
    def save_user(self, user: User) -> bool:
        """Save user to database"""
        with self.get_connection() as conn:
            if conn is None:
                # Mock mode - just return success
                self.logger.info(f"Mock mode: Would save user {user.username}")
                return True

            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_users (
                            id, username, email, full_name, roles, permissions,
                            is_active, created_at, last_login, password_hash, api_keys, security_clearance
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            username = EXCLUDED.username,
                            email = EXCLUDED.email,
                            full_name = EXCLUDED.full_name,
                            roles = EXCLUDED.roles,
                            permissions = EXCLUDED.permissions,
                            is_active = EXCLUDED.is_active,
                            last_login = EXCLUDED.last_login,
                            password_hash = EXCLUDED.password_hash,
                            api_keys = EXCLUDED.api_keys,
                            security_clearance = EXCLUDED.security_clearance
                    """,
                        (
                            user.id,
                            user.username,
                            user.email,
                            user.full_name,
                            user.roles,
                            user.permissions,
                            user.is_active,
                            user.created_at,
                            user.last_login,
                            user.password_hash,
                            user.api_keys,
                            user.security_clearance,
                        ),
                    )
                    conn.commit()
                    return True
            except Exception as e:
                self.logger.error(f"Failed to save user {user.id}: {e}")
                return False

    def load_user(self, user_id: str) -> Optional[User]:
        """Load user from database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    cursor.execute(
                        "SELECT * FROM security_users WHERE id = %s", (user_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        return User(
                            id=row["id"],
                            username=row["username"],
                            email=row["email"],
                            full_name=row["full_name"],
                            roles=row["roles"],
                            permissions=row["permissions"],
                            is_active=row["is_active"],
                            created_at=row["created_at"],
                            last_login=row["last_login"],
                            password_hash=row["password_hash"],
                            api_keys=row["api_keys"],
                            security_clearance=row["security_clearance"],
                        )
        except Exception as e:
            self.logger.error(f"Failed to load user {user_id}: {e}")
        return None

    def load_user_by_username(self, username: str) -> Optional[User]:
        """Load user by username"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    cursor.execute(
                        "SELECT * FROM security_users WHERE username = %s", (username,)
                    )
                    row = cursor.fetchone()
                    if row:
                        return User(
                            id=row["id"],
                            username=row["username"],
                            email=row["email"],
                            full_name=row["full_name"],
                            roles=row["roles"],
                            permissions=row["permissions"],
                            is_active=row["is_active"],
                            created_at=row["created_at"],
                            last_login=row["last_login"],
                            password_hash=row["password_hash"],
                            api_keys=row["api_keys"],
                            security_clearance=row["security_clearance"],
                        )
        except Exception as e:
            self.logger.error(f"Failed to load user by username {username}: {e}")
        return None

    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """List users from database"""
        users = []
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    cursor.execute(
                        """
                        SELECT * FROM security_users
                        ORDER BY created_at DESC
                        LIMIT %s OFFSET %s
                    """,
                        (limit, offset),
                    )
                    rows = cursor.fetchall()
                    for row in rows:
                        users.append(
                            User(
                                id=row["id"],
                                username=row["username"],
                                email=row["email"],
                                full_name=row["full_name"],
                                roles=row["roles"],
                                permissions=row["permissions"],
                                is_active=row["is_active"],
                                created_at=row["created_at"],
                                last_login=row["last_login"],
                                password_hash=row["password_hash"],
                                api_keys=row["api_keys"],
                                security_clearance=row["security_clearance"],
                            )
                        )
        except Exception as e:
            self.logger.error(f"Failed to list users: {e}")
        return users

    def delete_user(self, user_id: str) -> bool:
        """Delete user from database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM security_users WHERE id = %s", (user_id,)
                    )
                    conn.commit()
                    return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"Failed to delete user {user_id}: {e}")
            return False

    # Session Management Methods
    def save_session(self, session: Session) -> bool:
        """Save session to database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_sessions (
                            session_id, user_id, ip_address, user_agent,
                            created_at, expires_at, is_active
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (session_id) DO UPDATE SET
                            is_active = EXCLUDED.is_active
                    """,
                        (
                            session.session_id,
                            session.user_id,
                            session.ip_address,
                            session.user_agent,
                            session.created_at,
                            session.expires_at,
                            session.is_active,
                        ),
                    )
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Failed to save session {session.session_id}: {e}")
            return False

    def load_session(self, session_id: str) -> Optional[Session]:
        """Load session from database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    cursor.execute(
                        "SELECT * FROM security_sessions WHERE session_id = %s",
                        (session_id,),
                    )
                    row = cursor.fetchone()
                    if row:
                        return Session(
                            session_id=row["session_id"],
                            user_id=row["user_id"],
                            ip_address=row["ip_address"],
                            user_agent=row["user_agent"],
                            created_at=row["created_at"],
                            expires_at=row["expires_at"],
                            is_active=row["is_active"],
                        )
        except Exception as e:
            self.logger.error(f"Failed to load session {session_id}: {e}")
        return None

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        DELETE FROM security_sessions
                        WHERE expires_at < CURRENT_TIMESTAMP OR is_active = FALSE
                    """
                    )
                    deleted_count = cursor.rowcount
                    conn.commit()
                    return deleted_count
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0

    # Data Object Management Methods
    def save_data_object(self, data_object: DataObject) -> bool:
        """Save data object to database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_data_objects (
                            id, name, classification, category, owner_id,
                            created_at, last_modified, tags, metadata, access_log, retention_policy
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            classification = EXCLUDED.classification,
                            category = EXCLUDED.category,
                            last_modified = EXCLUDED.last_modified,
                            tags = EXCLUDED.tags,
                            metadata = EXCLUDED.metadata,
                            access_log = EXCLUDED.access_log,
                            retention_policy = EXCLUDED.retention_policy
                    """,
                        (
                            data_object.id,
                            data_object.name,
                            data_object.classification,
                            data_object.category,
                            data_object.owner_id,
                            data_object.created_at,
                            data_object.last_modified,
                            data_object.tags,
                            json.dumps(data_object.metadata),
                            json.dumps(data_object.access_log),
                            data_object.retention_policy,
                        ),
                    )
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Failed to save data object {data_object.id}: {e}")
            return False

    def load_data_object(self, data_id: str) -> Optional[DataObject]:
        """Load data object from database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    cursor.execute(
                        "SELECT * FROM security_data_objects WHERE id = %s", (data_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        return DataObject(
                            id=row["id"],
                            name=row["name"],
                            classification=row["classification"],
                            category=row["category"],
                            owner_id=row["owner_id"],
                            created_at=row["created_at"],
                            last_modified=row["last_modified"],
                            tags=row["tags"],
                            metadata=row["metadata"],
                            access_log=row["access_log"],
                            retention_policy=row["retention_policy"],
                        )
        except Exception as e:
            self.logger.error(f"Failed to load data object {data_id}: {e}")
        return None

    def list_data_objects(
        self,
        owner_id: str = None,
        classification: str = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[DataObject]:
        """List data objects from database"""
        data_objects = []
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    query = "SELECT * FROM security_data_objects WHERE 1=1"
                    params = []

                    if owner_id:
                        query += " AND owner_id = %s"
                        params.append(owner_id)

                    if classification:
                        query += " AND classification = %s"
                        params.append(classification)

                    query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
                    params.extend([limit, offset])

                    cursor.execute(query, params)
                    rows = cursor.fetchall()
                    for row in rows:
                        data_objects.append(
                            DataObject(
                                id=row["id"],
                                name=row["name"],
                                classification=row["classification"],
                                category=row["category"],
                                owner_id=row["owner_id"],
                                created_at=row["created_at"],
                                last_modified=row["last_modified"],
                                tags=row["tags"],
                                metadata=row["metadata"],
                                access_log=row["access_log"],
                                retention_policy=row["retention_policy"],
                            )
                        )
        except Exception as e:
            self.logger.error(f"Failed to list data objects: {e}")
        return data_objects

    def delete_data_object(self, data_id: str) -> bool:
        """Delete data object from database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM security_data_objects WHERE id = %s", (data_id,)
                    )
                    conn.commit()
                    return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"Failed to delete data object {data_id}: {e}")
            return False

    # Access Policy Management Methods
    def save_access_policy(self, policy: AccessPolicy) -> bool:
        """Save access policy to database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_access_policies (
                            resource_type, resource_id, user_id, role, permissions,
                            conditions, created_at, expires_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                        (
                            policy.resource_type,
                            policy.resource_id,
                            policy.user_id,
                            policy.role,
                            policy.permissions,
                            json.dumps(policy.conditions),
                            policy.created_at,
                            policy.expires_at,
                        ),
                    )
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Failed to save access policy: {e}")
            return False

    def load_access_policies(
        self, resource_type: str = None, resource_id: str = None, user_id: str = None
    ) -> List[AccessPolicy]:
        """Load access policies from database"""
        policies = []
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    query = "SELECT * FROM security_access_policies WHERE 1=1"
                    params = []

                    if resource_type:
                        query += " AND resource_type = %s"
                        params.append(resource_type)

                    if resource_id:
                        query += " AND resource_id = %s"
                        params.append(resource_id)

                    if user_id:
                        query += " AND user_id = %s"
                        params.append(user_id)

                    query += " ORDER BY created_at DESC"
                    cursor.execute(query, params)
                    rows = cursor.fetchall()
                    for row in rows:
                        policies.append(
                            AccessPolicy(
                                id=row["id"],
                                resource_type=row["resource_type"],
                                resource_id=row["resource_id"],
                                user_id=row["user_id"],
                                role=row["role"],
                                permissions=row["permissions"],
                                conditions=row["conditions"],
                                created_at=row["created_at"],
                                expires_at=row["expires_at"],
                            )
                        )
        except Exception as e:
            self.logger.error(f"Failed to load access policies: {e}")
        return policies

    # Security Events and Monitoring
    def save_security_event(self, event: SecurityEvent) -> bool:
        """Save security event to database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_events (
                            id, timestamp, event_type, severity, user_id,
                            ip_address, user_agent, details, source
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                        (
                            event.id,
                            event.timestamp,
                            event.event_type,
                            event.severity,
                            event.user_id,
                            event.ip_address,
                            event.user_agent,
                            json.dumps(event.details),
                            event.source,
                        ),
                    )
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Failed to save security event {event.id}: {e}")
            return False

    def save_security_alert(self, alert: SecurityAlert) -> bool:
        """Save security alert to database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_alerts (
                            id, timestamp, alert_type, severity, description,
                            affected_users, affected_data, recommended_actions,
                            status, assigned_to, resolved_at, notes
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            status = EXCLUDED.status,
                            assigned_to = EXCLUDED.assigned_to,
                            resolved_at = EXCLUDED.resolved_at,
                            notes = EXCLUDED.notes
                    """,
                        (
                            alert.id,
                            alert.timestamp,
                            alert.alert_type,
                            alert.severity,
                            alert.description,
                            alert.affected_users,
                            alert.affected_data,
                            alert.recommended_actions,
                            alert.status,
                            alert.assigned_to,
                            getattr(alert, "resolved_at", None),
                            getattr(alert, "notes", None),
                        ),
                    )
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Failed to save security alert {alert.id}: {e}")
            return False

    def get_security_events(
        self, days: int = 7, limit: int = 1000
    ) -> List[SecurityEvent]:
        """Get security events from database"""
        events = []
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    cursor.execute(
                        """
                        SELECT * FROM security_events
                        WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
                        ORDER BY timestamp DESC
                        LIMIT %s
                    """,
                        (days, limit),
                    )
                    rows = cursor.fetchall()
                    for row in rows:
                        events.append(
                            SecurityEvent(
                                id=row["id"],
                                timestamp=row["timestamp"],
                                event_type=row["event_type"],
                                severity=row["severity"],
                                user_id=row["user_id"],
                                ip_address=row["ip_address"],
                                user_agent=row["user_agent"],
                                details=row["details"],
                                source=row["source"],
                            )
                        )
        except Exception as e:
            self.logger.error(f"Failed to get security events: {e}")
        return events

    def get_security_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate security report from database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(
                    cursor_factory=psycopg2.extras.RealDictCursor
                ) as cursor:
                    # Get event statistics
                    cursor.execute(
                        """
                        SELECT
                            COUNT(*) as total_events,
                            COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_events,
                            COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_events,
                            COUNT(CASE WHEN event_type = 'authentication_failed' THEN 1 END) as failed_logins,
                            COUNT(CASE WHEN event_type = 'access_denied' THEN 1 END) as access_denials
                        FROM security_events
                        WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
                    """,
                        (days,),
                    )

                    stats = cursor.fetchone()

                    # Get top users by events
                    cursor.execute(
                        """
                        SELECT user_id, COUNT(*) as event_count
                        FROM security_events
                        WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
                          AND user_id IS NOT NULL
                        GROUP BY user_id
                        ORDER BY event_count DESC
                        LIMIT 10
                    """,
                        (days,),
                    )

                    top_users = cursor.fetchall()

                    return {
                        "period_days": days,
                        "total_events": stats["total_events"],
                        "critical_events": stats["critical_events"],
                        "high_events": stats["high_events"],
                        "failed_logins": stats["failed_logins"],
                        "access_denials": stats["access_denials"],
                        "top_users": [
                            {"user_id": u["user_id"], "event_count": u["event_count"]}
                            for u in top_users
                        ],
                    }
        except Exception as e:
            self.logger.error(f"Failed to generate security report: {e}")
            return {}

    def audit_log_action(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str = None,
        details: Dict = None,
        ip_address: str = None,
        user_agent: str = None,
        success: bool = True,
        error_message: str = None,
    ) -> bool:
        """Log audit action to database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO security_audit_log (
                            user_id, action, resource_type, resource_id,
                            details, ip_address, user_agent, success, error_message
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                        (
                            user_id,
                            action,
                            resource_type,
                            resource_id,
                            json.dumps(details or {}),
                            ip_address,
                            user_agent,
                            success,
                            error_message,
                        ),
                    )
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Failed to audit log action: {e}")
            return False

    def close(self):
        """Close database connections"""
        if self.pool:
            self.pool.closeall()
            self.logger.info("Database connections closed")


# Global database instance
security_db = SecurityDatabase()


def initialize_security_database():
    """Initialize the security database"""
    try:
        security_db.initialize_schema()
        return True
    except Exception as e:
        logging.error(f"Failed to initialize security database: {e}")
        return False
