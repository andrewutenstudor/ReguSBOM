"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Security Utilities: Sliding Window In-Memory Rate Limiting and Audit Event Recording.
Compliant with ENISA Table 7 and NIS2 Art. 21 Access Hardening.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.models.audit import AuditLog

logger = logging.getLogger("regubom.security")


class InMemoryRateLimiter:
    """
    Sliding-window in-memory rate limiter per client IP and action.
    Eliminates external Redis dependency while maintaining air-gap sovereignty.
    """

    def __init__(self):
        # Maps (ip, action) -> deque of timestamps
        self._history: dict[tuple, deque] = defaultdict(deque)

    def check(self, ip: str, action: str, max_attempts: int, window_seconds: int) -> bool:
        """
        Records attempt and checks if within limits.
        Returns True if allowed, False if exceeded.
        """
        now = time.time()
        key = (ip, action)
        dq = self._history[key]

        # Purge entries outside window
        cutoff = now - window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= max_attempts:
            return False

        dq.append(now)
        return True


rate_limiter = InMemoryRateLimiter()


def enforce_rate_limit(request: Request, action: str, max_attempts: int, window_seconds: int):
    """
    FastAPI helper raising HTTP 429 when rate limit is exceeded.
    Extracts client IP from X-Forwarded-For or client.host.
    """
    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    elif request.client and request.client.host:
        client_ip = request.client.host
    else:
        client_ip = "127.0.0.1"

    allowed = rate_limiter.check(client_ip, action, max_attempts, window_seconds)
    if not allowed:
        logger.warning(f"[RateLimit] Exceeded for IP '{client_ip}' on action '{action}'")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"RateLimitExceeded: Too many requests for '{action}'. Please retry in {window_seconds} seconds.",
        )


def record_audit_event(
    db: Session,
    action: str,
    user_id: str | None = None,
    ip_address: str | None = None,
    resource_type: str = "AUTH",
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog | None:
    """
    Records an immutable audit event in the database for compliance and non-repudiation.
    """
    try:
        log_entry = AuditLog(
            action=action,
            user_id=str(user_id) if user_id is not None else "anonymous",
            ip_address=ip_address,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            details=details or {},
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    except Exception as e:
        logger.error(f"[Audit] Failed to persist audit log for action '{action}': {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return None
