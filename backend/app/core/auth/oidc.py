"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Keycloak / OpenID Connect (OIDC) Enterprise SSO Provider.
Supports OpenID Connect discovery, authorization code flow, and role mapping.
"""

import logging
import os
import urllib.parse
from typing import Any

import httpx

from app.models.user import Role

logger = logging.getLogger("regubom.auth.oidc")

OIDC_ENABLED = os.environ.get("OIDC_ENABLED", "false").lower() in ("true", "1", "yes")
OIDC_DISCOVERY_URL = os.environ.get("OIDC_DISCOVERY_URL", "")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "regubom-gateway")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5173/login?oidc_callback=1")

_discovery_cache: dict[str, Any] | None = None


def is_oidc_enabled() -> bool:
    """Checks whether enterprise Keycloak/OIDC SSO is enabled."""
    return OIDC_ENABLED and bool(OIDC_DISCOVERY_URL.strip())


async def get_oidc_configuration() -> dict[str, Any] | None:
    """Fetches OpenID configuration from the discovery URL."""
    global _discovery_cache
    if not is_oidc_enabled():
        return None
    if _discovery_cache:
        return _discovery_cache

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(OIDC_DISCOVERY_URL)
            if resp.status_code == 200:
                _discovery_cache = resp.json()
                return _discovery_cache
            logger.warning(f"[OIDC] Discovery endpoint returned HTTP {resp.status_code}")
    except Exception as e:
        logger.error(f"[OIDC] Failed to fetch discovery document from '{OIDC_DISCOVERY_URL}': {e}")
    return None


async def get_authorization_url(state: str, redirect_uri: str | None = None) -> str | None:
    """Generates the Keycloak authorization URL to initiate SSO."""
    config = await get_oidc_configuration()
    eff_redirect = redirect_uri or OIDC_REDIRECT_URI

    auth_endpoint = config.get("authorization_endpoint") if config else None
    if not auth_endpoint:
        # Fallback if discovery is unreachable
        base = (
            OIDC_DISCOVERY_URL.rsplit("/.well-known", 1)[0]
            if OIDC_DISCOVERY_URL
            else "https://keycloak.corp.local/realms/enterprise"
        )
        auth_endpoint = f"{base}/protocol/openid-connect/auth"

    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": eff_redirect,
        "state": state,
    }
    return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"


async def exchange_code_for_user_info(code: str, redirect_uri: str | None = None) -> dict[str, Any] | None:
    """
    Exchanges the authorization code for tokens and fetches user profile.
    Extracts role from realm_access.roles or resource_access.
    """
    if not is_oidc_enabled():
        return None

    config = await get_oidc_configuration()
    eff_redirect = redirect_uri or OIDC_REDIRECT_URI

    token_endpoint = config.get("token_endpoint") if config else None
    if not token_endpoint:
        base = OIDC_DISCOVERY_URL.rsplit("/.well-known", 1)[0]
        token_endpoint = f"{base}/protocol/openid-connect/token"

    userinfo_endpoint = config.get("userinfo_endpoint") if config else None
    if not userinfo_endpoint:
        base = OIDC_DISCOVERY_URL.rsplit("/.well-known", 1)[0]
        userinfo_endpoint = f"{base}/protocol/openid-connect/userinfo"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_data = {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
                "redirect_uri": eff_redirect,
            }
            token_resp = await client.post(token_endpoint, data=token_data)
            if token_resp.status_code != 200:
                logger.error(f"[OIDC] Token exchange failed ({token_resp.status_code}): {token_resp.text}")
                return None

            tokens = token_resp.json()
            access_token = tokens.get("access_token")

            # Fetch userinfo
            userinfo_resp = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
            if userinfo_resp.status_code != 200:
                logger.error(f"[OIDC] Userinfo fetch failed ({userinfo_resp.status_code}): {userinfo_resp.text}")
                return None

            user_data = userinfo_resp.json()
            username = user_data.get("preferred_username") or user_data.get("sub") or user_data.get("email")
            email = user_data.get("email")
            full_name = user_data.get("name") or username

            # Role extraction
            roles: list[str] = []
            if "realm_access" in user_data and "roles" in user_data["realm_access"]:
                roles.extend(user_data["realm_access"]["roles"])
            if "resource_access" in user_data and OIDC_CLIENT_ID in user_data["resource_access"]:
                roles.extend(user_data["resource_access"][OIDC_CLIENT_ID].get("roles", []))
            if "roles" in user_data:
                roles.extend(user_data["roles"])

            roles_str = " ".join(roles).lower()
            if "admin" in roles_str:
                assigned_role = Role.ADMIN
            elif "auditor" in roles_str:
                assigned_role = Role.AUDITOR
            else:
                assigned_role = Role.OPERATOR

            return {
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": assigned_role,
                "is_oidc_user": True,
                "is_active": True,
            }
    except Exception as e:
        logger.error(f"[OIDC] Exception during code exchange: {e}")
        return None
