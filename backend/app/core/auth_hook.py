"""
ReguBOM — Authentication & Authorization Hook.
Provides a clean abstraction between Community Edition (Open Source)
and Enterprise Edition (Commercial Add-on):
- In Community Edition: open access dependency allowing unauthenticated access to public endpoints.
- In Enterprise Edition: delegates to EE RBAC engine (Role, require_role, get_current_user).
"""

import logging
import os
import sys
from collections.abc import Callable
from typing import Any

from fastapi import Request

logger = logging.getLogger("regubom.auth_hook")


def is_auth_enforced() -> bool:
    """
    Returns True only if running Enterprise Edition or explicitly configured via environment.
    In Community Edition (default), returns False so core routes (/api/validate, /api/reports)
    remain openly accessible without mandatory authentication barriers.
    """
    if os.getenv("AUTH_REQUIRED", "").lower() in ("0", "false", "no"):
        return False
    if os.getenv("AUTH_REQUIRED", "").lower() in ("1", "true", "yes"):
        return True
    edition = os.getenv("REGUBOM_EDITION", "community").lower()
    if edition in ("community", "ce"):
        return False
    if edition in ("ee", "enterprise"):
        return True
    if "ee.loader" in sys.modules:
        return True
    try:
        import ee.loader  # noqa: F401

        return True
    except (ImportError, ModuleNotFoundError):
        return False


def open_access_dependency(request: Request) -> Any | None:
    """Default no-op authorization dependency in Community Edition."""
    return None


async def get_optional_user(request: Request) -> Any | None:
    """
    Extracts authenticated user if credentials (X-API-Key, Bearer token, cookie) are provided;
    returns None if anonymous, never raising 401 in Community Edition.
    """
    try:
        from app.core.auth import get_current_user

        if (
            request.headers.get("X-API-Key")
            or request.headers.get("Authorization")
            or request.cookies.get("access_token")
        ):
            return await get_current_user(request)
    except Exception:
        pass
    return None


def require_role(roles: list[str] | None = None) -> Callable:
    """
    Role-Based Access Control hook.
    In CE (default): returns open access dependency allowing unauthenticated access.
    In EE (or when AUTH_REQUIRED=true): returns strict RBAC role verification.
    """
    if not is_auth_enforced():
        return open_access_dependency

    try:
        from app.core.auth import require_role as ee_require_role

        return ee_require_role(roles)
    except (ImportError, ModuleNotFoundError):
        return open_access_dependency
