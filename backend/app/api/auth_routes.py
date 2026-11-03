"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Authentication, Identity & Access Management Endpoints.
Features:
1. Hybrid Local DB, LDAP/AD, and Keycloak/OIDC Single Sign-On (SSO).
2. Multi-Factor Authentication (TOTP / Microsoft & Google Authenticator + Recovery Codes).
3. Least-Privilege Scoped Machine Tokens (CI/CD Pipelines).
4. Self-Service Password Reset via Configurable SMTP Mailer.
5. In-Memory Rate Limiting and Immutable Audit Logging.
Compliant with ENISA Table 7 and NIS2 Art. 21 Access Control Requirements.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import (
    Role,
    create_access_token,
    decode_access_token,
    generate_api_key,
    get_current_user,
    get_password_hash,
    require_role,
    verify_password,
)
from app.core.auth.ldap import authenticate_ldap, is_ldap_enabled
from app.core.auth.mfa import (
    generate_qr_code_base64,
    generate_recovery_codes,
    generate_totp_secret,
    generate_totp_uri,
    verify_and_consume_recovery_code,
    verify_totp_code,
)
from app.core.auth.oidc import (
    exchange_code_for_user_info,
    get_authorization_url,
    is_oidc_enabled,
)
from app.core.database import get_db
from app.core.mail import send_password_reset_email
from app.core.security import enforce_rate_limit, record_audit_event
from app.models.user import ApiKey, User

router = APIRouter(prefix="/api/auth", tags=["authentication"])


# ------------------------------------------------------------------------------
# Request / Response Schemas
# ------------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(..., description="Username or LDAP UPN")
    password: str = Field(..., description="User password")


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(..., description="Short-lived MFA challenge token")
    totp_code: str = Field(..., description="6-digit TOTP code or emergency recovery code")


class MfaEnableRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=6,
        max_length=10,
        description="Verification code from authenticator app",
    )


class MfaDisableRequest(BaseModel):
    password: str = Field(..., description="Current account password")
    totp_code: str = Field(..., description="Current TOTP code or recovery code")


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., description="Registered account email address")


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="One-time password reset token")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    email: str | None = None
    password: str = Field(..., min_length=8)
    role: str = Field("operator", description="'admin', 'operator', or 'auditor'")
    full_name: str | None = None


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Pipeline identifier (e.g. 'GitLab CI Prod')",
    )
    role: str = Field("operator", description="'admin', 'operator', or 'auditor'")
    expires_in_days: int | None = Field(None, description="Expiration in days (or null for non-expiring)")
    allowed_products: list[str] | None = Field(
        default=["*"],
        description="Allowed product slugs (e.g. ['core-gateway', 'edge-os']) or ['*'] for all",
    )


# ------------------------------------------------------------------------------
# Auth Providers Discovery
# ------------------------------------------------------------------------------
@router.get("/providers", summary="Discover active authentication identity providers")
async def get_auth_providers():
    """Returns status of enterprise identity providers (LDAP, OIDC, MFA)."""
    return {
        "ldap_enabled": is_ldap_enabled(),
        "oidc_enabled": is_oidc_enabled(),
        "mfa_supported": True,
    }


# ------------------------------------------------------------------------------
# Login & Session Management
# ------------------------------------------------------------------------------
@router.post(
    "/login",
    summary="Authenticate via Local Database or Corporate LDAP / Active Directory",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticates operator credentials against Local DB first, falling back to LDAP.
    Supports MFA challenge transition, sets HTTP-only session cookie, and returns JWT.
    Rate-limited to 5 attempts per minute per IP.
    """
    enforce_rate_limit(request, action="LOGIN", max_attempts=5, window_seconds=60)

    username = payload.username.strip()
    password = payload.password
    client_ip = request.client.host if request.client else "unknown"

    user_info: User | None = None

    # 1. Check Local DB users first (preserves break-glass admin access)
    local_user = db.query(User).filter(User.username == username).first()
    if local_user and local_user.hashed_password and verify_password(password, local_user.hashed_password):
        if not local_user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated.")
        local_user.last_login = datetime.utcnow()
        db.commit()
        db.refresh(local_user)
        user_info = local_user

    # 2. If local fails and LDAP is enabled, attempt LDAP bind & search
    if not user_info and is_ldap_enabled():
        ldap_profile = authenticate_ldap(username, password)
        if ldap_profile:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                user = User(
                    username=username,
                    email=ldap_profile.get("email"),
                    full_name=ldap_profile.get("full_name"),
                    role=Role.normalize(ldap_profile.get("role", "operator")),
                    is_ldap_user=True,
                    is_active=True,
                    created_at=datetime.utcnow(),
                    last_login=datetime.utcnow(),
                )
                db.add(user)
            else:
                user.role = Role.normalize(ldap_profile.get("role", user.role))
                user.full_name = ldap_profile.get("full_name", user.full_name)
                user.is_ldap_user = True
                user.last_login = datetime.utcnow()

            db.commit()
            db.refresh(user)
            user_info = user

    # 3. Authentication Failed
    if not user_info:
        record_audit_event(
            db=db,
            action="LOGIN_FAILED",
            user_id=username,
            ip_address=client_ip,
            details={"reason": "Invalid credentials", "username": username},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. MFA Challenge Check
    if user_info.mfa_enabled:
        mfa_token = create_access_token(
            data={
                "sub": user_info.username,
                "user_id": user_info.id,
                "type": "mfa_pending",
            },
            expires_delta=timedelta(minutes=5),
        )
        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "username": user_info.username,
        }

    # 5. Standard Login Success
    record_audit_event(
        db=db,
        action="LOGIN_SUCCESS",
        user_id=str(user_info.id),
        ip_address=client_ip,
        details={"username": user_info.username, "role": user_info.role},
    )

    normalized_role = Role.normalize(user_info.role)
    token_claims = {
        "sub": user_info.username,
        "username": user_info.username,
        "user_id": user_info.id,
        "role": normalized_role,
        "email": user_info.email,
        "full_name": user_info.full_name or user_info.username,
        "is_ldap_user": user_info.is_ldap_user,
        "is_oidc_user": getattr(user_info, "is_oidc_user", False),
    }
    access_token = create_access_token(data=token_claims)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=86400,
        samesite="lax",
        secure=False,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "user": user_info.to_dict(),
    }


# ------------------------------------------------------------------------------
# Multi-Factor Authentication (MFA / TOTP) Endpoints
# ------------------------------------------------------------------------------
@router.post("/mfa/verify", summary="Verify TOTP challenge during login")
async def verify_mfa_challenge(
    payload: MfaVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Exchanges short-lived MFA challenge token and TOTP code (or recovery code)
    for a full access JWT and session cookie.
    """
    claims = decode_access_token(payload.mfa_token)
    if not claims or claims.get("type") != "mfa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA verification session.",
        )

    username = claims.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification unavailable.",
        )

    client_ip = request.client.host if request.client else "unknown"
    code = payload.totp_code.strip()

    # Check TOTP code
    is_valid = verify_totp_code(user.mfa_secret, code)

    # Check emergency recovery code fallback
    used_recovery = False
    if not is_valid and user.mfa_recovery_codes:
        is_valid, updated_codes = verify_and_consume_recovery_code(code, user.mfa_recovery_codes)
        if is_valid:
            used_recovery = True
            user.mfa_recovery_codes = updated_codes
            db.commit()

    if not is_valid:
        record_audit_event(
            db=db,
            action="MFA_CHALLENGE_FAILED",
            user_id=str(user.id),
            ip_address=client_ip,
            details={"username": user.username},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication code. Please try again or use an emergency recovery code.",
        )

    record_audit_event(
        db=db,
        action="MFA_VERIFY_SUCCESS",
        user_id=str(user.id),
        ip_address=client_ip,
        details={"username": user.username, "used_recovery_code": used_recovery},
    )

    normalized_role = Role.normalize(user.role)
    token_claims = {
        "sub": user.username,
        "username": user.username,
        "user_id": user.id,
        "role": normalized_role,
        "email": user.email,
        "full_name": user.full_name or user.username,
        "is_ldap_user": user.is_ldap_user,
        "is_oidc_user": getattr(user, "is_oidc_user", False),
    }
    access_token = create_access_token(data=token_claims)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=86400,
        samesite="lax",
        secure=False,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "user": user.to_dict(),
    }


@router.post("/mfa/setup", summary="Initiate MFA setup and generate QR code")
async def setup_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Generates standard base32 TOTP secret and returns otpauth URI + base64 QR code.
    Saves temporary candidate secret to user until verified via /mfa/enable.
    """
    secret = generate_totp_secret()
    otpauth_uri = generate_totp_uri(current_user.username, secret)
    qr_code_b64 = generate_qr_code_base64(otpauth_uri)

    current_user.mfa_secret = secret
    db.commit()

    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "qr_code": qr_code_b64,
        "instructions": "Scan this QR code in Microsoft Authenticator or Google Authenticator, then verify with a 6-digit code to enable MFA.",
    }


@router.post("/mfa/enable", summary="Confirm and activate MFA")
async def enable_mfa(
    payload: MfaEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Verifies code against candidate secret, activates MFA, and generates
    8 emergency one-time recovery codes.
    """
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup has not been initiated. Call /mfa/setup first.",
        )

    if not verify_totp_code(current_user.mfa_secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit code. Check your authenticator app clock and try again.",
        )

    plain_codes, hashed_codes = generate_recovery_codes(8)
    current_user.mfa_enabled = True
    current_user.mfa_recovery_codes = hashed_codes
    db.commit()

    record_audit_event(
        db=db,
        action="MFA_ENABLED",
        user_id=str(current_user.id),
        details={"username": current_user.username},
    )

    return {
        "enabled": True,
        "recovery_codes": plain_codes,
        "message": "Two-Factor Authentication is now active. Store your emergency recovery codes safely.",
    }


@router.post("/mfa/disable", summary="Deactivate MFA")
async def disable_mfa(
    payload: MfaDisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Deactivates MFA after validating account password and code."""
    if not current_user.hashed_password or not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password confirmation.",
        )

    code_valid = False
    if current_user.mfa_secret:
        code_valid = verify_totp_code(current_user.mfa_secret, payload.totp_code)
    if not code_valid and current_user.mfa_recovery_codes:
        code_valid, _ = verify_and_consume_recovery_code(payload.totp_code, current_user.mfa_recovery_codes)

    if not code_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP or recovery code.",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_recovery_codes = None
    db.commit()

    record_audit_event(
        db=db,
        action="MFA_DISABLED",
        user_id=str(current_user.id),
        details={"username": current_user.username},
    )

    return {
        "enabled": False,
        "message": "Multi-Factor Authentication has been disabled.",
    }


# ------------------------------------------------------------------------------
# Keycloak / OpenID Connect (OIDC) SSO Endpoints
# ------------------------------------------------------------------------------
@router.get("/oidc/login", summary="Initiate Keycloak / OIDC Single Sign-On")
async def oidc_login():
    """Generates corporate SSO authorization redirect URL."""
    if not is_oidc_enabled():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Corporate OIDC Single Sign-On is not configured or enabled.",
        )
    state = secrets.token_urlsafe(16)
    auth_url = await get_authorization_url(state=state)
    return {"authorization_url": auth_url, "state": state}


@router.get("/oidc/callback", summary="Exchange OIDC authorization code for session")
async def oidc_callback(code: str, response: Response, request: Request, db: Session = Depends(get_db)):
    """Processes OIDC code exchange, provisions user, and sets session cookie."""
    if not is_oidc_enabled():
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="OIDC is not enabled.")

    profile = await exchange_code_for_user_info(code)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to authenticate with corporate OIDC identity provider.",
        )

    username = profile["username"]
    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            email=profile.get("email"),
            full_name=profile.get("full_name"),
            role=Role.normalize(profile.get("role", "operator")),
            is_oidc_user=True,
            is_active=True,
            created_at=datetime.utcnow(),
            last_login=datetime.utcnow(),
        )
        db.add(user)
    else:
        user.role = Role.normalize(profile.get("role", user.role))
        user.full_name = profile.get("full_name", user.full_name)
        user.is_oidc_user = True
        user.last_login = datetime.utcnow()

    db.commit()
    db.refresh(user)

    client_ip = request.client.host if request.client else "unknown"
    record_audit_event(
        db=db,
        action="LOGIN_SUCCESS",
        user_id=str(user.id),
        ip_address=client_ip,
        details={
            "provider": "OIDC/Keycloak",
            "username": user.username,
            "role": user.role,
        },
    )

    normalized_role = Role.normalize(user.role)
    token_claims = {
        "sub": user.username,
        "username": user.username,
        "user_id": user.id,
        "role": normalized_role,
        "email": user.email,
        "full_name": user.full_name or user.username,
        "is_oidc_user": True,
    }
    access_token = create_access_token(data=token_claims)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=86400,
        samesite="lax",
        secure=False,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "user": user.to_dict(),
    }


# ------------------------------------------------------------------------------
# Self-Service Password Reset
# ------------------------------------------------------------------------------
@router.post("/forgot-password", summary="Request a password reset link")
async def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """
    Initiates self-service password reset. Sends email if SMTP is configured.
    Rate-limited to 3 requests per 15 minutes per IP.
    Always returns generic success message to prevent user enumeration.
    """
    enforce_rate_limit(request, action="FORGOT_PASSWORD", max_attempts=3, window_seconds=900)

    clean_email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == clean_email, User.is_active == True).first()

    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        user.reset_token_hash = token_hash
        user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=15)
        db.commit()

        send_password_reset_email(user.email, user.username, raw_token)

        client_ip = request.client.host if request.client else "unknown"
        record_audit_event(
            db=db,
            action="PASSWORD_RESET_REQUESTED",
            user_id=str(user.id),
            ip_address=client_ip,
            details={"email": clean_email},
        )

    return {
        "message": "If this email address is registered, password reset instructions have been sent.",
    }


@router.post("/reset-password", summary="Reset password using one-time verification token")
async def reset_password(payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Validates reset token and sets new password."""
    token_hash = hashlib.sha256(payload.token.strip().encode("utf-8")).hexdigest()
    user = (
        db.query(User)
        .filter(
            User.reset_token_hash == token_hash,
            User.reset_token_expires_at > datetime.utcnow(),
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset link. Please request a new one.",
        )

    if len(payload.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )

    user.hashed_password = get_password_hash(payload.new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.commit()

    client_ip = request.client.host if request.client else "unknown"
    record_audit_event(
        db=db,
        action="PASSWORD_RESET_COMPLETED",
        user_id=str(user.id),
        ip_address=client_ip,
        details={"username": user.username},
    )

    return {"message": "Password has been successfully updated. You may now log in."}


# ------------------------------------------------------------------------------
# Session Endpoints
# ------------------------------------------------------------------------------
@router.post("/logout", summary="Log out of the current session")
async def logout(response: Response):
    """Clears the HTTP-only access_token cookie."""
    response.delete_cookie(key="access_token")
    return {"message": "Logged out successfully."}


@router.get("/me", summary="Get current authenticated user profile")
async def get_me(current_user: User = Depends(get_current_user)):
    """Returns the profile and effective role of the authenticated caller."""
    return current_user.to_dict()


# ------------------------------------------------------------------------------
# CI/CD Scoped Machine API Tokens
# ------------------------------------------------------------------------------
@router.post(
    "/api-keys",
    summary="Generate scoped machine API key for CI/CD pipelines",
    dependencies=[Depends(require_role(["admin", "operator"]))],
)
async def create_machine_token(
    payload: ApiKeyCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generates a secure CI/CD machine token (prefixed with rgb_live_...).
    Supports least-privilege scoping to specific product slugs or ['*'].
    The plain token string is returned ONLY ONCE upon creation.
    """
    allowed_prods = payload.allowed_products or ["*"]
    key_record, raw_token = generate_api_key(
        name=payload.name,
        role=payload.role,
        db=db,
        user_id=current_user.id if current_user.id > 0 else None,
        expires_in_days=payload.expires_in_days,
        allowed_products=allowed_prods,
    )

    record_audit_event(
        db=db,
        action="API_KEY_CREATED",
        user_id=str(current_user.id),
        details={
            "name": key_record.name,
            "role": key_record.role,
            "allowed_products": allowed_prods,
        },
    )

    return {
        "id": key_record.id,
        "name": key_record.name,
        "token": raw_token,
        "key_prefix": key_record.key_prefix,
        "role": key_record.role,
        "allowed_products": allowed_prods,
        "expires_at": key_record.expires_at.isoformat() if key_record.expires_at else None,
        "created_at": key_record.created_at.isoformat() if key_record.created_at else None,
        "instructions": "Store this machine token securely. It will not be shown again. Pass it as 'X-API-Key' or 'Authorization: Bearer <token>' in CI/CD pipelines.",
    }


@router.get(
    "/api-keys",
    summary="List machine API keys",
    dependencies=[Depends(require_role(["admin", "operator"]))],
)
async def list_machine_tokens(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Lists registered CI/CD API machine tokens (token secrets are redacted)."""
    keys = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
    return [k.to_dict() for k in keys]


@router.delete(
    "/api-keys/{key_id}",
    summary="Revoke a machine API key",
    dependencies=[Depends(require_role(["admin", "operator"]))],
)
async def revoke_machine_token(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Permanently revokes an API token."""
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="ApiKey not found.")

    key_name = key.name
    db.delete(key)
    db.commit()

    record_audit_event(
        db=db,
        action="API_KEY_REVOKED",
        user_id=str(current_user.id),
        details={"key_id": key_id, "name": key_name},
    )

    return {"message": f"API Key '{key_name}' (id={key_id}) has been revoked."}


# ------------------------------------------------------------------------------
# User Management (Admin Only)
# ------------------------------------------------------------------------------
@router.get(
    "/users",
    summary="List all registered system users",
    dependencies=[Depends(require_role(["admin"]))],
)
async def list_users(db: Session = Depends(get_db)):
    """Lists all user accounts in ReguBOM."""
    users = db.query(User).order_by(User.id.asc()).all()
    return [u.to_dict() for u in users]


@router.post(
    "/users",
    summary="Create a new system user",
    dependencies=[Depends(require_role(["admin"]))],
)
async def create_user(payload: UserCreateRequest, db: Session = Depends(get_db)):
    """Creates a local operator or auditor account."""
    existing = db.query(User).filter(User.username == payload.username.strip()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with username '{payload.username}' already exists.",
        )

    user = User(
        username=payload.username.strip(),
        email=payload.email.strip() if payload.email else None,
        hashed_password=get_password_hash(payload.password),
        role=Role.normalize(payload.role),
        full_name=payload.full_name.strip() if payload.full_name else payload.username.strip(),
        is_ldap_user=False,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user.to_dict()
