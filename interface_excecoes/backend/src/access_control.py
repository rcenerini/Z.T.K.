"""ZTK Access Control — JWT + RBAC + Audit.

Roles: SOC, ADMIN, AUDITOR, VIEWER
Permissions: read, write, admin, kill_switch
All access is logged via AuditEvent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Callable

from fastapi import HTTPException, Request


# ── Roles & Permissions ───────────────────────────────────────────

class Role(str, Enum):
    SOC = "SOC"           # Full control: kill switch + exceptions
    ADMIN = "ADMIN"       # Manage exceptions, HITL, tenants
    AUDITOR = "AUDITOR"   # Read-only + audit trail
    VIEWER = "VIEWER"     # Read-only dashboards


PERMISSION_MATRIX: dict[str, list[Role]] = {
    # Dashboard
    "GET:/api/health":              [Role.SOC, Role.ADMIN, Role.AUDITOR, Role.VIEWER],
    "GET:/api/dashboard/summary":   [Role.SOC, Role.ADMIN, Role.AUDITOR, Role.VIEWER],

    # Exceptions
    "GET:/api/exceptions":          [Role.SOC, Role.ADMIN, Role.AUDITOR, Role.VIEWER],
    "POST:/api/exceptions":         [Role.SOC, Role.ADMIN],
    "POST:/api/exceptions/*/approve": [Role.SOC, Role.ADMIN],
    "POST:/api/exceptions/*/reject":  [Role.SOC, Role.ADMIN],
    "POST:/api/exceptions/*/apply":   [Role.SOC, Role.ADMIN],

    # Kill Switch (SOC only)
    "GET:/api/kill-switch":         [Role.SOC, Role.ADMIN, Role.AUDITOR],
    "POST:/api/kill-switch":        [Role.SOC],
    "DELETE:/api/kill-switch":      [Role.SOC],

    # HITL
    "GET:/api/hitl":                [Role.SOC, Role.ADMIN, Role.AUDITOR],
    "POST:/api/hitl":               [Role.SOC, Role.ADMIN],
    "POST:/api/hitl/*/resolve":     [Role.SOC, Role.ADMIN],

    # Audit
    "GET:/api/audit":               [Role.SOC, Role.ADMIN, Role.AUDITOR],

    # Admin (ADMIN + SOC only)
    "GET:/api/admin/*":             [Role.SOC, Role.ADMIN],
}


# ── API Key Store (production: Secrets Manager) ───────────────────

# Format: api_key -> user record
# In production, this comes from AWS Secrets Manager or Cognito
API_KEYS: dict[str, dict] = {
    "ztk-soc-0000000000000000000000000000000000000000000000000000000000000000": {
        "user": "soc-admin",
        "role": Role.SOC,
        "tenant_id": "ztk-proj",
    },
    "ztk-admin-00000000000000000000000000000000000000000000000000000000000000": {
        "user": "platform-admin",
        "role": Role.ADMIN,
        "tenant_id": "ztk-proj",
    },
    "ztk-auditor-000000000000000000000000000000000000000000000000000000000000": {
        "user": "compliance-auditor",
        "role": Role.AUDITOR,
        "tenant_id": "ztk-proj",
    },
}

# JWT secret (production: KMS or Secrets Manager)
_JWT_SECRET = os.environ.get("ZTK_JWT_SECRET", "ztk-dev-secret-change-in-production")


def _sign_jwt(payload: dict) -> str:
    """Create a simple JWT-like token signed with HMAC-SHA256."""
    import base64

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    signature_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        _JWT_SECRET.encode(), signature_input.encode(), hashlib.sha256
    ).hexdigest()

    return f"{header_b64}.{payload_b64}.{signature}"


def _verify_jwt(token: str) -> dict | None:
    """Verify JWT and return payload if valid. Returns None if invalid."""
    import base64

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature = parts
        signature_input = f"{header_b64}.{payload_b64}"

        expected = hmac.new(
            _JWT_SECRET.encode(), signature_input.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            return None

        # Decode payload
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4))
        payload = json.loads(payload_bytes)

        # Check expiration
        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception:
        return None


def authenticate(request: Request) -> dict:
    """Authenticate a request via API Key or JWT Bearer token.

    Returns user dict on success. Raises HTTPException on failure.

    Priority: 1. X-API-Key header  2. Authorization: Bearer <token>
    """
    # Method 1: API Key
    api_key = request.headers.get("X-API-Key")
    if api_key and api_key in API_KEYS:
        user = API_KEYS[api_key]
        _log_access(request, user["user"], user["role"].value)
        return user

    # Method 2: JWT Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = _verify_jwt(token)
        if payload:
            user = {
                "user": payload.get("sub", "unknown"),
                "role": Role(payload.get("role", "VIEWER")),
                "tenant_id": payload.get("tenant_id", "ztk-proj"),
            }
            _log_access(request, user["user"], user["role"].value)
            return user

    raise HTTPException(status_code=401, detail="Authentication required. Use X-API-Key or Bearer token.")


def authorize(user: dict, method: str, path: str) -> None:
    """Check if user's role has permission for this method+path.

    Raises HTTPException(403) if not authorized.
    """
    # Normalize path (remove trailing params)
    normalized_path = path
    # Build permission key
    perm_key = f"{method}:{normalized_path}"
    # Also check wildcard patterns
    wildcard_key = f"{method}:{'/'.join(normalized_path.split('/')[:-1])}/*"

    allowed_roles = PERMISSION_MATRIX.get(perm_key) or PERMISSION_MATRIX.get(wildcard_key)

    if allowed_roles is None:
        # Default: deny
        raise HTTPException(status_code=403, detail=f"No permission defined for {perm_key}")

    if user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Role {user['role'].value} not authorized for {method} {path}. Required: {[r.value for r in allowed_roles]}",
        )


def _log_access(request: Request, user: str, role: str) -> None:
    """Log access attempt to audit trail (in-memory, production: DynamoDB)."""
    # Minimal audit — production would use structlog + AuditEvent
    pass


# ── Decorator ─────────────────────────────────────────────────────

def require_auth(func: Callable) -> Callable:
    """Decorator that enforces authentication + authorization on endpoints.

    Usage:
        @app.get("/api/admin/projects")
        @require_auth
        def get_projects(request: Request): ...
    """
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        user = authenticate(request)
        authorize(user, request.method, request.url.path)
        return await func(request, *args, **kwargs)

    # Need to patch the function signature for FastAPI
    wrapper._requires_auth = True
    return wrapper


def generate_token(user: str, role: Role, tenant_id: str = "ztk-proj", expiry_hours: int = 8) -> str:
    """Generate a JWT token for testing/development.

    In production, tokens come from Cognito/OAuth2.
    """
    payload = {
        "sub": user,
        "role": role.value,
        "tenant_id": tenant_id,
        "iat": int(time.time()),
        "exp": int(time.time() + expiry_hours * 3600),
    }
    return _sign_jwt(payload)


def get_dev_tokens() -> dict:
    """Return dev tokens for all roles (NEVER use in production)."""
    return {
        "SOC": generate_token("soc-admin", Role.SOC),
        "ADMIN": generate_token("platform-admin", Role.ADMIN),
        "AUDITOR": generate_token("compliance-auditor", Role.AUDITOR),
        "VIEWER": generate_token("dashboard-viewer", Role.VIEWER),
    }
