"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Immutable Audit Log Query & Compliance Export Endpoints.
Accessible by ADMIN and AUDITOR roles. Supports JSON pagination & CSV streaming export.
"""

import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.auth.roles import Role, require_role
from app.core.database import get_db
from app.models.audit import AuditLog

router = APIRouter(prefix="/api/admin", tags=["audit-logging"])


@router.get(
    "/audit-logs",
    summary="Query Immutable Regulatory Audit Logs (Admin & Auditor Only)",
    dependencies=[Depends(require_role([Role.ADMIN, Role.AUDITOR]))],
)
async def get_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=500, description="Records per page"),
    action: str | None = Query(None, description="Filter by action name (e.g. UPLOAD_SBOM_TIER)"),
    resource_type: str | None = Query(None, description="Filter by resource type (e.g. ARTIFACT, PRODUCT)"),
    user_id: str | None = Query(None, description="Filter by operator username"),
    from_date: str | None = Query(None, description="ISO from timestamp (e.g. 2026-01-01)"),
    to_date: str | None = Query(None, description="ISO to timestamp (e.g. 2026-12-31)"),
    format: str = Query("json", regex="^(json|csv)$", description="Export format: json or csv"),
    db: Session = Depends(get_db),
):
    """
    Retrieves regulatory audit records with pagination, filtering, and CSV export.
    Enforces accountability as required by EU CRA Article 13 & NIS2.
    """
    query = db.query(AuditLog)

    if isinstance(action, str) and action.strip():
        query = query.filter(AuditLog.action.ilike(f"%{action.strip()}%"))
    if isinstance(resource_type, str) and resource_type.strip():
        query = query.filter(AuditLog.resource_type == resource_type.strip().upper())
    if isinstance(user_id, str) and user_id.strip():
        query = query.filter(AuditLog.user_id.ilike(f"%{user_id.strip()}%"))

    if isinstance(from_date, str) and from_date.strip():
        try:
            dt_from = datetime.fromisoformat(from_date.replace("Z", "+00:00"))
            query = query.filter(AuditLog.timestamp >= dt_from)
        except ValueError:
            pass

    if isinstance(to_date, str) and to_date.strip():
        try:
            dt_to = datetime.fromisoformat(to_date.replace("Z", "+00:00"))
            query = query.filter(AuditLog.timestamp <= dt_to)
        except ValueError:
            pass

    # Order newest first
    query = query.order_by(desc(AuditLog.timestamp))

    # CSV Export Handler
    if isinstance(format, str) and format.lower() == "csv":
        # Fetch up to 5000 records for CSV export
        records = query.limit(5000).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Audit ID",
                "Timestamp (UTC)",
                "User ID",
                "Action",
                "Resource Type",
                "Resource ID",
                "Client IP",
                "HTTP Method",
                "HTTP Status",
                "Duration (ms)",
                "Details",
            ]
        )

        for log in records:
            details = log.details or {}
            writer.writerow(
                [
                    log.id,
                    log.timestamp.isoformat() if log.timestamp else "",
                    log.user_id or "anonymous",
                    log.action,
                    log.resource_type,
                    log.resource_id or "",
                    log.ip_address or "",
                    details.get("method", ""),
                    details.get("status_code", ""),
                    details.get("duration_ms", ""),
                    json.dumps(details),
                ]
            )

        output.seek(0)
        filename = f"regubom_audit_trail_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Cache-Control": "no-cache",
            },
        )

    # JSON Paginated Response
    total = query.count()
    offset = (page - 1) * limit
    logs = query.offset(offset).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, (total + limit - 1) // limit),
        "audit_logs": [log.to_dict() for log in logs],
    }
