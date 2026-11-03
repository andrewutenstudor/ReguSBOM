"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Immutable Audit Logging Middleware.
Captures all mutating requests (POST, PUT, DELETE, PATCH) into the audit_logs table.
Compliant with EU Cyber Resilience Act (CRA Art. 13 & Annex II) traceability requirements.
"""

import asyncio
import logging
import time
from datetime import datetime

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.auth.jwt_handler import decode_access_token
from app.core.database import SessionLocal
from app.models.audit import AuditLog

logger = logging.getLogger("regubom.audit")


def _determine_audit_action(method: str, path: str) -> tuple[str, str, str | None]:
    """Derives action name, resource type, and resource id from request method and path."""
    clean_path = path.strip("/").split("/")
    # default action and resource
    action = f"{method.upper()}_{clean_path[-1].upper() if clean_path else 'ROOT'}"
    resource_type = clean_path[1].upper() if len(clean_path) > 1 else "SYSTEM"
    resource_id = None

    if "upload" in path and "releases" in path:
        action = "UPLOAD_SBOM_TIER"
        resource_type = "ARTIFACT"
        if len(clean_path) >= 3:
            resource_id = f"{clean_path[2]}:{clean_path[4] if len(clean_path) > 4 else 'latest'}"
    elif "validate" in path:
        action = "AUDIT_SBOM"
        resource_type = "REPORT"
    elif "products" in path:
        resource_type = "PRODUCT"
        if method == "POST":
            action = "CREATE_PRODUCT" if len(clean_path) == 2 else "CREATE_RELEASE"
        elif method == "DELETE":
            action = "DELETE_PRODUCT" if len(clean_path) == 3 else "DELETE_RELEASE"
            resource_id = clean_path[2] if len(clean_path) > 2 else None
        elif method == "PATCH":
            action = "UPDATE_RELEASE"
            resource_id = clean_path[-1]
    elif "license" in path:
        resource_type = "LICENSE"
        action = "INSTALL_LICENSE" if "upload" in path else "UPDATE_LICENSE"
    elif "auth" in path:
        resource_type = "AUTH"
        action = "LOGIN_TRANSACTION" if "login" in path else "USER_MANAGEMENT"
    elif "reports" in path and method == "DELETE":
        action = "DELETE_REPORT"
        resource_type = "REPORT"
        resource_id = clean_path[-1]

    return action, resource_type, resource_id


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Captures mutating HTTP operations into the immutable regulatory audit trail."""

    EXEMPT_PATHS = ("/health", "/api/health", "/docs", "/redoc", "/openapi.json")

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path

        # Only audit mutating transactions
        if method not in ("POST", "PUT", "DELETE", "PATCH") or path in self.EXEMPT_PATHS:
            return await call_next(request)

        start_time = time.time()

        # 1. Extract operator identity from Authorization Bearer token
        user_id = "anonymous"
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)
            if payload and "sub" in payload:
                user_id = payload["sub"]

        # 2. Extract Client IP
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        elif request.client and request.client.host:
            ip_address = request.client.host
        else:
            ip_address = "127.0.0.1"

        action, resource_type, resource_id = _determine_audit_action(method, path)

        # Execute transaction
        response = await call_next(request)

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # Record log asynchronously in background
        asyncio.create_task(
            self._record_audit_log_async(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                details={
                    "method": method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": elapsed_ms,
                    "user_agent": request.headers.get("user-agent", "N/D")[:150],
                },
            )
        )

        return response

    async def _record_audit_log_async(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str | None,
        ip_address: str,
        details: dict,
    ):
        """Persists audit record in a dedicated database session."""
        try:
            db = SessionLocal()
            try:
                log_entry = AuditLog(
                    timestamp=datetime.utcnow(),
                    user_id=user_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=ip_address,
                    details=details,
                )
                db.add(log_entry)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.error(f"[Audit] Failed to persist audit log: {e}")
