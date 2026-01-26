"""
Medic Agent Authentication

API authentication and authorization for the Web API.
Supports API key authentication with role-based access control.
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from core.logger import get_logger

logger = get_logger("interfaces.auth")

try:
    from fastapi import HTTPException, Request, Security, status
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


class Role(Enum):
    """User roles for RBAC."""
    ADMIN = "admin"          # Full access
    OPERATOR = "operator"    # Can approve/deny resurrections
    VIEWER = "viewer"        # Read-only access
    API = "api"              # Service account for API access


class Permission(Enum):
    """Granular permissions."""
    # Queue operations
    VIEW_QUEUE = "queue:view"
    APPROVE_RESURRECTION = "queue:approve"
    DENY_RESURRECTION = "queue:deny"

    # Decision operations
    VIEW_DECISIONS = "decisions:view"

    # Resurrection operations
    VIEW_RESURRECTIONS = "resurrections:view"
    ROLLBACK_RESURRECTION = "resurrections:rollback"

    # Outcome operations
    VIEW_OUTCOMES = "outcomes:view"
    SUBMIT_FEEDBACK = "outcomes:feedback"

    # Configuration operations
    VIEW_CONFIG = "config:view"
    UPDATE_CONFIG = "config:update"
    UPDATE_THRESHOLDS = "config:thresholds"

    # Report operations
    VIEW_REPORTS = "reports:view"

    # Monitoring operations
    VIEW_MONITORS = "monitors:view"
    STOP_MONITOR = "monitors:stop"


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.VIEWER: {
        Permission.VIEW_QUEUE,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_RESURRECTIONS,
        Permission.VIEW_OUTCOMES,
        Permission.VIEW_CONFIG,
        Permission.VIEW_REPORTS,
        Permission.VIEW_MONITORS,
    },
    Role.OPERATOR: {
        Permission.VIEW_QUEUE,
        Permission.APPROVE_RESURRECTION,
        Permission.DENY_RESURRECTION,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_RESURRECTIONS,
        Permission.ROLLBACK_RESURRECTION,
        Permission.VIEW_OUTCOMES,
        Permission.SUBMIT_FEEDBACK,
        Permission.VIEW_CONFIG,
        Permission.VIEW_REPORTS,
        Permission.VIEW_MONITORS,
        Permission.STOP_MONITOR,
    },
    Role.ADMIN: set(Permission),  # All permissions
    Role.API: {
        Permission.VIEW_QUEUE,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_RESURRECTIONS,
        Permission.VIEW_OUTCOMES,
        Permission.VIEW_REPORTS,
        Permission.VIEW_MONITORS,
    },
}


@dataclass
class APIKey:
    """API key with metadata."""
    key_id: str
    key_hash: str  # SHA-256 hash of the actual key
    name: str
    role: Role
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    enabled: bool = True
    metadata: Dict[str, str] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if API key is valid."""
        if not self.enabled:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def has_permission(self, permission: Permission) -> bool:
        """Check if this key has a specific permission."""
        return permission in ROLE_PERMISSIONS.get(self.role, set())


class APIKeyStore:
    """
    Store and validate API keys.

    In production, this should be backed by a database or secrets manager.
    For now, we use environment variables and in-memory storage.
    """

    def __init__(self):
        self._keys: Dict[str, APIKey] = {}
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Load API keys from environment variables."""
        # Load admin key from environment
        admin_key = os.environ.get("MEDIC_ADMIN_API_KEY")
        if admin_key:
            self.add_key_from_plain(
                key_plain=admin_key,
                key_id="admin",
                name="Admin API Key",
                role=Role.ADMIN,
            )
            logger.info("Loaded admin API key from environment")

        # Load operator key from environment
        operator_key = os.environ.get("MEDIC_OPERATOR_API_KEY")
        if operator_key:
            self.add_key_from_plain(
                key_plain=operator_key,
                key_id="operator",
                name="Operator API Key",
                role=Role.OPERATOR,
            )
            logger.info("Loaded operator API key from environment")

        # Load viewer key from environment
        viewer_key = os.environ.get("MEDIC_VIEWER_API_KEY")
        if viewer_key:
            self.add_key_from_plain(
                key_plain=viewer_key,
                key_id="viewer",
                name="Viewer API Key",
                role=Role.VIEWER,
            )
            logger.info("Loaded viewer API key from environment")

        if not self._keys:
            logger.warning(
                "No API keys loaded! Set MEDIC_ADMIN_API_KEY, "
                "MEDIC_OPERATOR_API_KEY, or MEDIC_VIEWER_API_KEY environment variables"
            )

    def add_key_from_plain(
        self,
        key_plain: str,
        key_id: str,
        name: str,
        role: Role,
        expires_at: Optional[datetime] = None,
    ) -> None:
        """Add an API key from plaintext (for initial setup)."""
        key_hash = self._hash_key(key_plain)
        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            role=role,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        self._keys[key_id] = api_key
        logger.debug(f"Added API key: {key_id} with role {role.value}")

    def validate_key(self, key_plain: str) -> Optional[APIKey]:
        """
        Validate an API key and return the associated APIKey object.

        Uses constant-time comparison to prevent timing attacks.
        """
        key_hash = self._hash_key(key_plain)

        for api_key in self._keys.values():
            # Constant-time comparison
            if self._constant_time_compare(key_hash, api_key.key_hash):
                if api_key.is_valid():
                    # Update last used timestamp
                    api_key.last_used = datetime.now(timezone.utc)
                    return api_key
                else:
                    logger.warning(f"Invalid or expired API key: {api_key.key_id}")
                    return None

        logger.warning("Unknown API key attempted")
        return None

    def _hash_key(self, key: str) -> str:
        """Hash an API key using SHA-256."""
        return hashlib.sha256(key.encode()).hexdigest()

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        return hmac.compare_digest(a, b)

    def generate_key(self) -> str:
        """Generate a secure random API key."""
        # Generate 32 bytes (256 bits) of randomness
        return secrets.token_urlsafe(32)

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        if key_id in self._keys:
            self._keys[key_id].enabled = False
            logger.info(f"Revoked API key: {key_id}")
            return True
        return False

    def list_keys(self) -> List[APIKey]:
        """List all API keys (for admin purposes)."""
        return list(self._keys.values())


# Global API key store
_api_key_store = APIKeyStore()


if FASTAPI_AVAILABLE:
    # HTTP Bearer security scheme
    security = HTTPBearer()


    async def verify_api_key(
        credentials: HTTPAuthorizationCredentials = Security(security),
    ) -> APIKey:
        """
        Verify API key from Authorization header.

        Usage:
            @app.get("/endpoint", dependencies=[Depends(verify_api_key)])
            async def endpoint():
                ...
        """
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        api_key = _api_key_store.validate_key(credentials.credentials)

        if not api_key:
            logger.warning("Invalid API key authentication attempt")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return api_key


    def require_permission(permission: Permission):
        """
        Dependency to require a specific permission.

        Usage:
            @app.post("/endpoint", dependencies=[Depends(require_permission(Permission.APPROVE_RESURRECTION))])
            async def endpoint():
                ...
        """
        async def permission_checker(api_key: APIKey = Security(verify_api_key)) -> APIKey:
            if not api_key.has_permission(permission):
                logger.warning(
                    f"Permission denied: {api_key.key_id} lacks {permission.value}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permission.value}",
                )
            return api_key

        return permission_checker


    def require_role(role: Role):
        """
        Dependency to require a specific role.

        Usage:
            @app.post("/endpoint", dependencies=[Depends(require_role(Role.ADMIN))])
            async def endpoint():
                ...
        """
        async def role_checker(api_key: APIKey = Security(verify_api_key)) -> APIKey:
            if api_key.role != role and api_key.role != Role.ADMIN:
                logger.warning(
                    f"Role denied: {api_key.key_id} has role {api_key.role.value}, requires {role.value}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges. Required role: {role.value}",
                )
            return api_key

        return role_checker


    async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Security(security),
    ) -> APIKey:
        """Get current authenticated user (alias for verify_api_key)."""
        return await verify_api_key(credentials)


def get_api_key_store() -> APIKeyStore:
    """Get the global API key store."""
    return _api_key_store
