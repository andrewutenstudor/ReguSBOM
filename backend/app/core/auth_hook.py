"""
ReguBOM — Authentication & Authorization Hook.
Provides a clean abstraction between Community Edition (Open Source)
and Enterprise Edition (Commercial Add-on):
- In Community Edition: no-op dependency (open access, self-hosted, standalone).
- In Enterprise Edition: delegates to EE RBAC engine (Role, require_role, get_current_user).
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import Request

logger = logging.getLogger("regubom.auth_hook")


def open_access_dependency(request: Request) -> Any | None:
    """Default no-op authorization dependency in Community Edition."""
    return None


def require_role(roles: list[str] | None = None) -> Callable:
    """
    Role-Based Access Control hook.
    In CE: returns an open access dependency.
    In EE: returns the strict RBAC role verification dependency.
    """
    try:
        from app.core.auth import require_role as ee_require_role

        return ee_require_role(roles)
    except (ImportError, ModuleNotFoundError):
        return open_access_dependency
