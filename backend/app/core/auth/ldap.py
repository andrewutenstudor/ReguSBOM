"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
LDAP & Active Directory Authentication Provider.
Integrates corporate directory authentication with local RBAC mapping.
"""
import logging
import os
from typing import Optional, Dict, Any, List
from app.models.user import Role

logger = logging.getLogger("regubom.auth.ldap")

LDAP_ENABLED = os.environ.get("LDAP_ENABLED", "false").lower() in ("true", "1", "yes")
LDAP_SERVER_URI = os.environ.get("LDAP_SERVER_URI") or os.environ.get("LDAP_SERVER", "ldap://dc.corp.local:389")
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=regubom,dc=local")
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
LDAP_USER_SEARCH_FILTER = os.environ.get("LDAP_USER_SEARCH_FILTER", "(|(sAMAccountName={username})(uid={username}))")
LDAP_ADMIN_GROUP = os.environ.get("LDAP_ADMIN_GROUP", "ReguBOM-Admins")
LDAP_OPERATOR_GROUP = os.environ.get("LDAP_OPERATOR_GROUP") or os.environ.get("LDAP_RELEASE_MANAGER_GROUP", "ReguBOM-Operators")
LDAP_AUDITOR_GROUP = os.environ.get("LDAP_AUDITOR_GROUP", "ReguBOM-Auditors")


def is_ldap_enabled() -> bool:
    """Checks whether enterprise LDAP directory integration is enabled."""
    return LDAP_ENABLED and bool(LDAP_SERVER_URI.strip())


def authenticate_ldap(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticates user against corporate LDAP / Active Directory.
    Returns authenticated user attributes or None if authentication fails.
    """
    if not is_ldap_enabled() or not username or not password:
        return None

    try:
        import ldap3
        server = ldap3.Server(LDAP_SERVER_URI, get_info=ldap3.ALL)

        user_dn = None
        user_groups: List[str] = []
        user_email = f"{username}@regubom.internal"
        user_fullname = username

        # 1. Search for user DN using service account if configured
        if LDAP_BIND_DN and LDAP_BIND_PASSWORD:
            admin_conn = ldap3.Connection(
                server,
                user=LDAP_BIND_DN,
                password=LDAP_BIND_PASSWORD,
                auto_bind=True
            )
            search_filter = LDAP_USER_SEARCH_FILTER.format(username=username)
            admin_conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=search_filter,
                attributes=['dn', 'mail', 'displayName', 'cn', 'memberOf']
            )
            if admin_conn.entries:
                entry = admin_conn.entries[0]
                user_dn = entry.entry_dn
                if 'mail' in entry and entry.mail.value:
                    user_email = str(entry.mail.value)
                if 'displayName' in entry and entry.displayName.value:
                    user_fullname = str(entry.displayName.value)
                if 'memberOf' in entry and entry.memberOf.values:
                    user_groups = [str(g) for g in entry.memberOf.values]
            admin_conn.unbind()
        else:
            # Direct UPN / DN bind attempt
            user_dn = f"{username}@{LDAP_BASE_DN.replace('dc=', '').replace(',', '.')}"

        if not user_dn:
            user_dn = f"uid={username},{LDAP_BASE_DN}"

        # 2. Attempt user credential bind
        user_conn = ldap3.Connection(server, user=user_dn, password=password)
        if not user_conn.bind():
            logger.warning(f"[LDAP] Credential validation failed for user '{username}' on '{LDAP_SERVER_URI}'")
            return None

        user_conn.unbind()
        logger.info(f"[LDAP] Successfully validated credentials for '{username}' via LDAP")

        # 3. Derive internal RBAC Role from LDAP groups
        assigned_role = Role.OPERATOR
        groups_str = " ".join(user_groups).lower()
        if LDAP_ADMIN_GROUP.lower() in groups_str or "admin" in groups_str:
            assigned_role = Role.ADMIN
        elif LDAP_AUDITOR_GROUP.lower() in groups_str or "auditor" in groups_str:
            assigned_role = Role.AUDITOR
        elif LDAP_OPERATOR_GROUP.lower() in groups_str or "operator" in groups_str or "releasemanager" in groups_str:
            assigned_role = Role.OPERATOR

        return {
            "username": username,
            "email": user_email,
            "full_name": user_fullname,
            "role": assigned_role,
            "is_ldap_user": True,
            "is_active": True,
        }
    except Exception as e:
        logger.error(f"[LDAP] Connection or lookup error for user '{username}': {e}")
        return None
