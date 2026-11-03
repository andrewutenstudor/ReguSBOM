"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Offline Cryptographic License Verifier & Air-Gap Zero-Telemetry Engine.
Uses Ed25519 public-key signature verification with no external network calls.
"""
import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("regubom.licensing")

# Candidate locations for license.lic
LICENSE_SEARCH_PATHS = [
    Path("license.lic"),
    Path("backend/license.lic"),
    Path("/app/license.lic"),
    Path(__file__).resolve().parent.parent.parent / "license.lic",
    Path(__file__).resolve().parent / "license.lic",
]

PUBLIC_KEY_PATH = Path(__file__).resolve().parent / "keys" / "license_pub.pem"


class LicenseStatus:
    """Represents the validated license state."""
    def __init__(
        self,
        is_valid: bool,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
        days_remaining: int = 0
    ):
        self.is_valid = is_valid
        self.error_code = error_code
        self.error_message = error_message
        self.claims = claims or {}
        self.days_remaining = days_remaining

    @property
    def customer_id(self) -> str:
        return self.claims.get("customer_id", "UNLICENSED")

    @property
    def customer_name(self) -> str:
        return self.claims.get("customer_name", "Unregistered Enterprise")

    @property
    def max_products(self) -> int:
        return int(self.claims.get("max_products", 0))

    @property
    def expiry_date(self) -> Optional[str]:
        return self.claims.get("expiry_date")

    @property
    def airgap_authorized(self) -> bool:
        return bool(self.claims.get("airgap_authorized", False))

    @property
    def tier(self) -> str:
        return self.claims.get("tier", "Air-Gapped Sovereign")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.is_valid,
            "status": "ACTIVE" if self.is_valid else (self.error_code or "INVALID"),
            "customer_id": self.customer_id,
            "customer_name": self.customer_name,
            "max_products": self.max_products,
            "expiry_date": self.expiry_date,
            "days_remaining": self.days_remaining,
            "airgap_authorized": self.airgap_authorized,
            "tier": self.tier,
            "features": self.claims.get("features", []),
            "error": self.error_message if not self.is_valid else None,
        }


class LicenseVerifier:
    """
    Ed25519 Cryptographic Verifier for Offline Sovereign Air-Gap Licenses.
    Zero-telemetry: never dials out, never validates against remote endpoints.
    """
    _cached_status: Optional[LicenseStatus] = None
    _last_checked: float = 0.0

    @classmethod
    def load_vendor_public_key(cls) -> ed25519.Ed25519PublicKey:
        """Loads the embedded vendor Ed25519 public key."""
        if not PUBLIC_KEY_PATH.exists():
            raise FileNotFoundError(
                f"Vendor verification public key not found at: {PUBLIC_KEY_PATH}"
            )
        with open(PUBLIC_KEY_PATH, "rb") as f:
            key_bytes = f.read()
        return serialization.load_pem_public_key(key_bytes)

    @classmethod
    def find_license_file(cls) -> Optional[Path]:
        """Scans standard air-gap search paths for license.lic."""
        for p in LICENSE_SEARCH_PATHS:
            if p.exists() and p.is_file():
                return p.resolve()
        return None

    @classmethod
    def verify(cls, license_file_path: Optional[Path] = None, force_refresh: bool = False) -> LicenseStatus:
        """
        Verifies license authenticity, claims integrity, and expiry.
        """
        now = datetime.now(timezone.utc)

        # Cache check for 10 seconds to avoid filesystem overhead on hot routes
        if not force_refresh and cls._cached_status and (now.timestamp() - cls._last_checked < 10):
            return cls._cached_status

        target_file = license_file_path or cls.find_license_file()
        if not target_file or not target_file.exists():
            status = LicenseStatus(
                is_valid=False,
                error_code="LICENSE_NOT_FOUND",
                error_message="Offline license file 'license.lic' not found. Please place a valid license in the application directory."
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                license_data = json.load(f)
        except Exception as e:
            status = LicenseStatus(
                is_valid=False,
                error_code="LICENSE_CORRUPT",
                error_message=f"Unable to parse license file as JSON: {e}"
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        # 1. Structure Verification
        claims = license_data.get("claims")
        signature_b64 = license_data.get("signature")

        if not isinstance(claims, dict) or not isinstance(signature_b64, str):
            status = LicenseStatus(
                is_valid=False,
                error_code="LICENSE_INVALID_FORMAT",
                error_message="License file missing required 'claims' object or 'signature' string."
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        # 2. Cryptographic Signature Verification
        try:
            public_key = cls.load_vendor_public_key()
            signature_bytes = base64.b64decode(signature_b64)
            canonical_claims_bytes = json.dumps(claims, sort_keys=True, separators=(',', ':')).encode('utf-8')
            public_key.verify(signature_bytes, canonical_claims_bytes)
        except InvalidSignature:
            status = LicenseStatus(
                is_valid=False,
                error_code="INVALID_SIGNATURE",
                error_message="Cryptographic signature verification failed. The license has been tampered with or was not issued by the vendor."
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status
        except Exception as e:
            status = LicenseStatus(
                is_valid=False,
                error_code="VERIFICATION_ERROR",
                error_message=f"Cryptographic verification error: {e}"
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        # 3. Claims Verification (customer_id, expiry_date, airgap_authorized)
        customer_id = claims.get("customer_id")
        if not customer_id:
            status = LicenseStatus(
                is_valid=False,
                error_code="MISSING_CUSTOMER_ID",
                error_message="License is missing mandatory 'customer_id' claim.",
                claims=claims
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        airgap_auth = claims.get("airgap_authorized")
        if not airgap_auth:
            status = LicenseStatus(
                is_valid=False,
                error_code="AIRGAP_UNAUTHORIZED",
                error_message="License is not authorized for air-gapped sovereign deployment.",
                claims=claims
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        expiry_str = claims.get("expiry_date")
        if not expiry_str:
            status = LicenseStatus(
                is_valid=False,
                error_code="MISSING_EXPIRY",
                error_message="License is missing mandatory 'expiry_date' claim.",
                claims=claims
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        try:
            # Parse ISO 8601 expiry timestamp
            expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        except Exception as e:
            status = LicenseStatus(
                is_valid=False,
                error_code="INVALID_EXPIRY_FORMAT",
                error_message=f"Invalid expiry_date format: {e}",
                claims=claims
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        # Check expiration against current UTC time
        if now > expiry_dt:
            status = LicenseStatus(
                is_valid=False,
                error_code="LICENSE_EXPIRED",
                error_message=f"License expired on {expiry_str}. Please renew your air-gapped license.",
                claims=claims,
                days_remaining=0
            )
            cls._cached_status = status
            cls._last_checked = now.timestamp()
            return status

        # Compute days remaining
        days_remaining = max(0, (expiry_dt - now).days)

        status = LicenseStatus(
            is_valid=True,
            claims=claims,
            days_remaining=days_remaining
        )
        cls._cached_status = status
        cls._last_checked = now.timestamp()
        return status


# ---------------------------------------------------------------------------
# License Enforcing Middleware
# ---------------------------------------------------------------------------
class LicenseEnforcementMiddleware(BaseHTTPMiddleware):
    """
    HTTP Middleware checking license validity on all mutating routes (POST, PUT, DELETE, PATCH).
    Exempts:
      - GET / HEAD / OPTIONS requests
      - Documentation (/docs, /redoc, /openapi.json)
      - Healthcheck endpoints (/health, /api/health)
      - License management endpoints (/api/license, /api/license/upload)
    If the license is invalid or expired, aborts the mutating request with 403 Forbidden.
    """
    EXEMPT_PREFIXES = (
        "/docs",
        "/redoc",
        "/openapi.json",
        "/health",
        "/api/health",
        "/api/license",
    )

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path

        # Only enforce on mutating HTTP methods
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            # Check exemptions
            if not any(path.startswith(prefix) for prefix in self.EXEMPT_PREFIXES):
                status = LicenseVerifier.verify()
                if not status.is_valid:
                    logger.warning(
                        f"[License] Mutating request {method} {path} blocked: "
                        f"{status.error_code} - {status.error_message}"
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "LicenseExpired" if status.error_code == "LICENSE_EXPIRED" else "LicenseInvalid",
                            "error_code": status.error_code or "LICENSE_INVALID",
                            "detail": f"{status.error_code}: {status.error_message}",
                            "license_status": status.to_dict(),
                        }
                    )

        response = await call_next(request)
        return response
