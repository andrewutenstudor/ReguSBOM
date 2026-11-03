"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Re-exports Role and require_role from app.core.auth.
"""
from app.core.auth import Role, require_role, get_current_user, get_current_active_user

__all__ = ["Role", "require_role", "get_current_user", "get_current_active_user"]
