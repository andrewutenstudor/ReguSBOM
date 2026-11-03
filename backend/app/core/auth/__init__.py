"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Local & LDAP Authentication, RBAC Engine, Password Hashing, JWT Sessions & CI/CD API Tokens.
Compliant with ENISA Table 7 and NIS2 Art. 21 Access Control Requirements.
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import bcrypt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal, get_db
from app.models.user import ApiKey, Role, User

logger = logging.getLogger("regubom.auth")

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "regubom-enterprise-sovereign-jwt-secret-key-2026-airgap")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security_bearer = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------------------
# Cryptographic Password Hashing (bcrypt + PBKDF2 fallback)
# ------------------------------------------------------------------------------
def get_password_hash(password: str) -> str:
    """Hash password with bcrypt."""
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > 72:
        pw_bytes = pw_bytes[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash or legacy PBKDF2 hash."""
    if not hashed_password or not plain_password:
        return False
    try:
        if hashed_password.startswith(("$2b$", "$2a$", "$2y$")):
            pw_bytes = plain_password.encode("utf-8")
            if len(pw_bytes) > 72:
                pw_bytes = pw_bytes[:72]
            return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))
        elif hashed_password.startswith("pbkdf2_sha256$"):
            parts = hashed_password.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2].encode("ascii"))
            expected_key = base64.b64decode(parts[3].encode("ascii"))
            key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(key, expected_key)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False
    return False


# ------------------------------------------------------------------------------
# JWT Session Management
# ------------------------------------------------------------------------------
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(UTC)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)

    to_encode.update(
        {
            "exp": expire,
            "iat": now,
            "iss": "regubom-gateway",
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Decode and validate JWT access token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ------------------------------------------------------------------------------
# CI/CD Machine API Tokens
# ------------------------------------------------------------------------------
def hash_api_key(raw_token: str) -> str:
    """Cryptographic SHA-256 hash of API token."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def generate_api_key(
    name: str,
    role: str,
    db: Session,
    user_id: int | None = None,
    expires_in_days: int | None = None,
    allowed_products: list[str] | None = None,
) -> tuple[ApiKey, str]:
    """
    Generate a machine token for CI/CD pipelines (e.g., rgb_live_...).
    Supports least-privilege scoping to specific product slugs or ['*'].
    Returns (ApiKey database model, raw_token_string).
    """
    token_suffix = secrets.token_urlsafe(32)
    raw_key = f"rgb_live_{token_suffix}"
    key_hash = hash_api_key(raw_key)

    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    normalized_role = Role.normalize(role)
    eff_allowed = allowed_products if allowed_products else ["*"]

    api_key_record = ApiKey(
        name=name.strip(),
        key_hash=key_hash,
        key_prefix="rgb_live_",
        role=normalized_role,
        user_id=user_id,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
        allowed_products=eff_allowed,
    )
    db.add(api_key_record)
    db.commit()
    db.refresh(api_key_record)

    return api_key_record, raw_key


# ------------------------------------------------------------------------------
# Current User & Machine Token Resolution Dependency
# ------------------------------------------------------------------------------
async def get_current_user(
    request: Request,
    bearer_auth: HTTPAuthorizationCredentials | None = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency extracting authenticated user or machine identity.
    Accepts:
      1. X-API-Key header (CI/CD pipeline machine token)
      2. Authorization: Bearer <token> (JWT token or machine token)
      3. access_token cookie (HTTP-only browser session)
    """
    token: str | None = None

    # 1. Check X-API-Key header
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header:
        token = api_key_header.strip()

    # 2. Check Authorization Bearer header
    if not token and bearer_auth and bearer_auth.credentials:
        token = bearer_auth.credentials.strip()

    # 3. Check HTTP-only cookie
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="AuthenticationRequired: Missing Bearer token, access cookie, or X-API-Key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Detect if token is an API Machine Key (starts with rgb_)
    if token.startswith("rgb_"):
        key_hash = hash_api_key(token)
        api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="InvalidApiKey: The provided machine token was not found or has been revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if api_key.is_expired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="ApiKeyExpired: Machine token has expired.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        api_key.last_used_at = datetime.utcnow()
        db.commit()

        allowed = api_key.allowed_products if api_key.allowed_products else ["*"]
        if api_key.user and api_key.user.is_active:
            user = api_key.user
            user.role = api_key.role
            user.allowed_products = allowed
            user.is_machine_token = True
            user.api_key_id = api_key.id
            return user

        synthetic_user = User(
            id=-(api_key.id),
            username=f"ci-token:{api_key.name}",
            email=f"ci-{api_key.name}@regubom.internal",
            role=api_key.role,
            is_active=True,
            full_name=f"CI/CD Pipeline ({api_key.name})",
        )
        synthetic_user.allowed_products = allowed
        synthetic_user.is_machine_token = True
        synthetic_user.api_key_id = api_key.id
        return synthetic_user

    # Handle JWT Bearer Token
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="InvalidToken: JWT token has expired or is malformed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") == "mfa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MfaPending: Complete MFA verification to establish full access session.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: str | None = payload.get("sub") or payload.get("username")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="InvalidTokenPayload: 'sub' / 'username' missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"UserNotFound: User '{username}' does not exist in the database.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"UserDisabled: Account '{username}' is disabled.",
        )

    user.allowed_products = ["*"]
    user.is_machine_token = False
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Dependency verifying user is active."""
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")
    return current_user


# ------------------------------------------------------------------------------
# RBAC Route Authorization Dependency Factory
# ------------------------------------------------------------------------------
def require_role(allowed_roles: list[str] | str):
    """
    FastAPI dependency guarding endpoints by role.
    Role hierarchy:
      - 'admin': Root privileges across all operations.
      - 'operator': Permitted on ingestion, upload, release registration, and viewing.
      - 'auditor': Read-only access to matrix, viewer, diff, reports, certificates.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    normalized_allowed = {Role.normalize(r) for r in allowed_roles}
    normalized_allowed.add(Role.ADMIN)

    if Role.AUDITOR in normalized_allowed:
        normalized_allowed.add(Role.OPERATOR)
        normalized_allowed.add(Role.ADMIN)

    async def _role_guard(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        user_role = Role.normalize(current_user.role)
        if user_role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"PermissionDenied: User '{current_user.username}' with role '{user_role}' "
                f"is not authorized. Required: {sorted(list(normalized_allowed))}",
            )
        return current_user

    return _role_guard


# ------------------------------------------------------------------------------
# Seed Default Users on Startup
# ------------------------------------------------------------------------------
def seed_default_users(db: Session) -> None:
    """
    Seeds initial default users on first startup if no users exist.
    Admin account: username: 'admin', password: 'AdminPassword2026!'
    Also provisions baseline operator and auditor accounts for immediate airgap usability.
    """
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            email="admin@regubom.internal",
            hashed_password=get_password_hash("AdminPassword2026!"),
            full_name="System Administrator",
            role=Role.ADMIN,
            is_active=True,
            is_ldap_user=False,
            created_at=datetime.utcnow(),
        )
        db.add(admin_user)
        logger.info("Default administrator account seeded: username='admin'")
    else:
        if not verify_password("AdminPassword2026!", admin_user.hashed_password or ""):
            admin_user.hashed_password = get_password_hash("AdminPassword2026!")
            admin_user.role = Role.ADMIN
            db.commit()

    operator_user = db.query(User).filter(User.username == "operator").first()
    if not operator_user:
        operator_user = User(
            username="operator",
            email="operator@regubom.internal",
            hashed_password=get_password_hash("OperatorPassword2026!"),
            full_name="Compliance Operator",
            role=Role.OPERATOR,
            is_active=True,
            is_ldap_user=False,
            created_at=datetime.utcnow(),
        )
        db.add(operator_user)
        logger.info("Default operator account seeded: username='operator'")
    else:
        if not verify_password("OperatorPassword2026!", operator_user.hashed_password or ""):
            operator_user.hashed_password = get_password_hash("OperatorPassword2026!")
            operator_user.role = Role.OPERATOR
            db.commit()

    auditor_user = db.query(User).filter(User.username == "auditor").first()
    if not auditor_user:
        auditor_user = User(
            username="auditor",
            email="auditor@regubom.internal",
            hashed_password=get_password_hash("AuditorPassword2026!"),
            full_name="Regulatory Auditor",
            role=Role.AUDITOR,
            is_active=True,
            is_ldap_user=False,
            created_at=datetime.utcnow(),
        )
        db.add(auditor_user)
        logger.info("Default auditor account seeded: username='auditor'")
    else:
        if not verify_password("AuditorPassword2026!", auditor_user.hashed_password or ""):
            auditor_user.hashed_password = get_password_hash("AuditorPassword2026!")
            auditor_user.role = Role.AUDITOR
            db.commit()

    db.commit()


__all__ = [
    "Role",
    "create_access_token",
    "decode_access_token",
    "generate_api_key",
    "get_current_active_user",
    "get_current_user",
    "get_password_hash",
    "hash_api_key",
    "require_role",
    "seed_default_users",
    "verify_password",
]
