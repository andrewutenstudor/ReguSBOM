"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
SQLAlchemy User and ApiKey Models for Local/LDAP/OIDC RBAC Authentication,
MFA / TOTP support, Scoped Machine Tokens, and Self-Service Password Resets.
Compliant with ENISA Table 7 and NIS2 Art. 21 Access Control.
Roles: 'admin', 'operator', 'auditor'.
"""
from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class Role:
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"

    # Backward compatibility aliases
    RELEASE_MANAGER = "operator"
    DEVELOPER = "operator"

    ALL = [ADMIN, OPERATOR, AUDITOR]

    @classmethod
    def normalize(cls, role_str: str) -> str:
        """Normalize role to lowercase standard ('admin', 'operator', 'auditor')."""
        if not role_str:
            return cls.AUDITOR
        r = role_str.lower().strip()
        if r in ["admin", "administrator"]:
            return cls.ADMIN
        if r in ["operator", "release_manager", "developer"]:
            return cls.OPERATOR
        return cls.AUDITOR


class User(Base):
    """Represents a local, LDAP, or OIDC-authenticated user in ReguBOM."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    hashed_password = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False, default=Role.OPERATOR, index=True)
    is_ldap_user = Column(Boolean, default=False, nullable=False)
    is_oidc_user = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Multi-Factor Authentication (MFA / TOTP)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_recovery_codes = Column(JSON, nullable=True)

    # Self-Service Password Reset
    reset_token_hash = Column(String(255), nullable=True, index=True)
    reset_token_expires_at = Column(DateTime, nullable=True)

    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name or self.username,
            "role": Role.normalize(self.role),
            "is_ldap_user": self.is_ldap_user,
            "is_oidc_user": self.is_oidc_user,
            "is_active": self.is_active,
            "mfa_enabled": bool(self.mfa_enabled),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class ApiKey(Base):
    """
    Machine token model for CI/CD pipeline integration and automated SBOM ingestion.
    Supports least-privilege scoping: `allowed_products` specifies product slugs or ['*'].
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False, index=True)
    key_prefix = Column(String(16), nullable=False, default="rgb_live_")
    role = Column(String(50), nullable=False, default=Role.OPERATOR)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    # Scoped permissions: list of product slugs or ['*'] for all
    allowed_products = Column(JSON, nullable=False, default=list)

    user = relationship("User", back_populates="api_keys")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def is_product_allowed(self, product_slug: str) -> bool:
        """Verify if this key is authorized to access/upload to the given product slug."""
        if not self.allowed_products:
            return True  # default backwards compatibility
        if "*" in self.allowed_products:
            return True
        return product_slug in self.allowed_products

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "role": Role.normalize(self.role),
            "user_id": self.user_id,
            "allowed_products": self.allowed_products if self.allowed_products else ["*"],
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "is_expired": self.is_expired,
        }
