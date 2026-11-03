"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
JWT Token Management & PBKDF2 Cryptographic Password Hashing.
FastAPI Dependency injection for RBAC user authentication.
"""
import base64
import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.auth.roles import Role
from app.models.user import User

logger = logging.getLogger("regubom.auth.jwt")

# Secret key for JWT signing
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "regubom-enterprise-sovereign-jwt-secret-key-2026-airgap")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Cryptographic Password Hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------
def get_password_hash(password: str) -> str:
    """Generates a secure PBKDF2-HMAC-SHA256 salted password hash."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"pbkdf2_sha256$100000${salt_b64}${key_b64}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored PBKDF2 hash."""
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2].encode("ascii"))
        expected_key = base64.b64decode(parts[3].encode("ascii"))
        key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(key, expected_key)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT Token Generation & Decoding
# ---------------------------------------------------------------------------
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT bearer token containing user claims and role."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({
        "exp": expire,
        "iat": now,
        "iss": "ReguBOM Gateway",
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates JWT bearer token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# FastAPI Auth Dependencies
# ---------------------------------------------------------------------------
async def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> User:
    """Dependency extracting current authenticated user from Bearer JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials. Bearer token missing or invalid.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not auth or not auth.credentials:
        raise credentials_exception

    payload = decode_access_token(auth.credentials)
    if not payload:
        raise credentials_exception

    username: str = payload.get("sub")
    if not username:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if not user:
        # Check if LDAP user needs JIT (Just-In-Time) provisioning
        if payload.get("is_ldap_user"):
            user = User(
                username=username,
                email=payload.get("email"),
                full_name=payload.get("full_name", username),
                role=payload.get("role", Role.DEVELOPER),
                is_ldap_user=True,
                is_active=True,
                created_at=datetime.utcnow()
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            raise credentials_exception

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Ensures current user is active."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user account.")
    return current_user


# ---------------------------------------------------------------------------
# Default Admin & Role Seeding
# ---------------------------------------------------------------------------
def seed_default_users(db: Session) -> None:
    """Seeds baseline RBAC accounts if users table is empty."""
    user_count = db.query(User).count()
    if user_count == 0:
        logger.info("[Auth] Initializing default enterprise RBAC user accounts...")
        defaults = [
            ("admin", "admin@regubom.internal", "ReguBOM@Admin2026!", Role.ADMIN, "System Administrator"),
            ("relmanager", "release@regubom.internal", "ReguBOM@Release2026!", Role.RELEASE_MANAGER, "Release & Compliance Manager"),
            ("developer", "dev@regubom.internal", "ReguBOM@Dev2026!", Role.DEVELOPER, "Software Engineer"),
            ("auditor", "audit@regubom.internal", "ReguBOM@Audit2026!", Role.AUDITOR, "Regulatory Compliance Auditor"),
        ]
        for uname, email, pwd, role, fullname in defaults:
            user = User(
                username=uname,
                email=email,
                hashed_password=get_password_hash(pwd),
                role=role,
                full_name=fullname,
                is_active=True,
                is_ldap_user=False,
                created_at=datetime.utcnow()
            )
            db.add(user)
        db.commit()
        logger.info("[Auth] Successfully created default accounts: admin, relmanager, developer, auditor.")
