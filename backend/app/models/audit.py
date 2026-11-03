"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
SQLAlchemy AuditLog Model for Immutable Regulatory Audit Trails.
Compliant with EU Cyber Resilience Act (CRA Art. 13 & Annex II) accountability requirements.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, Index
from app.core.database import Base


class AuditLog(Base):
    """
    Immutable audit log entry recording all mutating transactions and access events.
    Fields: id, timestamp (UTC), user_id, action, resource_type, resource_id, ip_address, details (JSON).
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(String(100), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(100), nullable=True)
    ip_address = Column(String(50), nullable=True)
    details = Column(JSON, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id or "anonymous",
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "details": self.details or {},
        }
