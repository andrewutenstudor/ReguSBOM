"""Backward-compatible re-exports for LDAP authentication."""

from app.core.auth.ldap import (
    LDAP_ADMIN_GROUP,
    LDAP_AUDITOR_GROUP,
    LDAP_BASE_DN,
    LDAP_ENABLED,
    LDAP_OPERATOR_GROUP,
    LDAP_SERVER_URI,
    authenticate_ldap,
    is_ldap_enabled,
)

__all__ = [
    "LDAP_ADMIN_GROUP",
    "LDAP_AUDITOR_GROUP",
    "LDAP_BASE_DN",
    "LDAP_ENABLED",
    "LDAP_OPERATOR_GROUP",
    "LDAP_SERVER_URI",
    "authenticate_ldap",
    "is_ldap_enabled",
]
