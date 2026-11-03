"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Re-exports Role and require_role from app.core.auth.
"""

from app.core.auth import Role, get_current_active_user, get_current_user, require_role

__all__ = ["Role", "get_current_active_user", "get_current_user", "require_role"]
