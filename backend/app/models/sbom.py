"""SQLAlchemy models for SBOM records and validation reports."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean, Float
from app.core.database import Base


class SBOMRecord(Base):
    """Model representing an uploaded SBOM file."""
    __tablename__ = "sbom_records"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_path = Column(String(512), nullable=False)
    sbom_format = Column(String(50), nullable=False)  # "cyclonedx" or "spdx"
    schema_version = Column(String(50), nullable=True)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)
    sbom_data = Column(JSON, nullable=True)  # Parsed SBOM content

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "original_filename": self.original_filename,
            "file_size": self.file_size,
            "sbom_format": self.sbom_format,
            "schema_version": self.schema_version,
            "upload_timestamp": self.upload_timestamp.isoformat() if self.upload_timestamp else None,
        }


class ValidationReport(Base):
    """Model representing a validation report."""
    __tablename__ = "validation_reports"

    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, nullable=False, index=True)
    report_filename = Column(String(255), nullable=False)
    report_path = Column(String(512), nullable=False)
    overall_status = Column(String(50), nullable=False)  # "PASS", "FAIL", "WARNING"
    overall_valid = Column(Boolean, default=False)
    processing_time = Column(Float, nullable=True)
    validation_timestamp = Column(DateTime, default=datetime.utcnow)
    report_data = Column(JSON, nullable=False)  # Full structured report

    def to_dict(self):
        return {
            "id": self.id,
            "sbom_id": self.sbom_id,
            "report_filename": self.report_filename,
            "overall_status": self.overall_status,
            "overall_valid": self.overall_valid,
            "processing_time": self.processing_time,
            "validation_timestamp": self.validation_timestamp.isoformat() if self.validation_timestamp else None,
        }
