"""Backward-compatible re-exports for LDAP authentication."""
from app.core.auth.ldap import (
    is_ldap_enabled,
    authenticate_ldap,
    LDAP_ENABLED,
    LDAP_SERVER_URI,
    LDAP_BASE_DN,
    LDAP_ADMIN_GROUP,
    LDAP_OPERATOR_GROUP,
    LDAP_AUDITOR_GROUP,
)

__all__ = [
    "is_ldap_enabled",
    "authenticate_ldap",
    "LDAP_ENABLED",
    "LDAP_SERVER_URI",
    "LDAP_BASE_DN",
    "LDAP_ADMIN_GROUP",
    "LDAP_OPERATOR_GROUP",
    "LDAP_AUDITOR_GROUP",
]
