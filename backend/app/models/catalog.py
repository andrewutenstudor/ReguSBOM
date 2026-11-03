"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
SQLAlchemy Models for Product & Release Asset Catalog.
Hierarchical mapping: Product -> ProductRelease -> SBOMArtifact (OS, CONTAINER, APPLICATION, FIRMWARE).
"""

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class Product(Base):
    """
    Represents a commercial software product, appliance, or system.
    Root entity of the Regulatory Asset Catalog.
    """

    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    business_unit = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships with cascading delete
    releases = relationship(
        "ProductRelease",
        back_populates="product",
        cascade="all, delete-orphan",
        order_by="desc(ProductRelease.created_at)",
    )

    def to_dict(self, include_releases: bool = False):
        data = {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "business_unit": self.business_unit,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "release_count": len(self.releases) if self.releases is not None else 0,
        }

        if self.releases:
            latest = self.releases[0]
            data["latest_release"] = latest.version
            data["latest_status"] = latest.lifecycle_status
            # Determine overall compliance of latest release
            statuses = [a.overall_status for a in latest.artifacts] if latest.artifacts else []
            if "FAIL" in statuses:
                data["latest_verdict"] = "FAIL"
            elif "WARNING" in statuses:
                data["latest_verdict"] = "WARNING"
            elif "PASS" in statuses:
                data["latest_verdict"] = "PASS"
            else:
                data["latest_verdict"] = "NO_ARTIFACTS"
        else:
            data["latest_release"] = None
            data["latest_status"] = None
            data["latest_verdict"] = "NO_RELEASES"

        if include_releases and self.releases is not None:
            data["releases"] = [r.to_dict(include_artifacts=True) for r in self.releases]

        return data


class ProductRelease(Base):
    """
    Represents a specific versioned release of a product (e.g. 'v2.1.0').
    Tracks lifecycle status: DRAFT -> VALIDATED -> RELEASED -> EOL.
    """

    __tablename__ = "product_releases"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(
        Integer,
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version = Column(String(100), nullable=False, index=True)
    release_date = Column(DateTime, nullable=True)
    lifecycle_status = Column(
        String(50), nullable=False, default="DRAFT", index=True
    )  # DRAFT, VALIDATED, RELEASED, EOL
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    product = relationship("Product", back_populates="releases")
    artifacts = relationship(
        "SBOMArtifact",
        back_populates="release",
        cascade="all, delete-orphan",
        order_by="desc(SBOMArtifact.created_at)",
    )

    __table_args__ = (UniqueConstraint("product_id", "version", name="uq_product_release_version"),)

    def to_dict(self, include_artifacts: bool = True):
        artifacts_list = self.artifacts or []
        statuses = [a.overall_status for a in artifacts_list]
        tiers = list(set([a.tier for a in artifacts_list]))

        if "FAIL" in statuses:
            verdict = "FAIL"
        elif "WARNING" in statuses:
            verdict = "WARNING"
        elif "PASS" in statuses:
            verdict = "PASS"
        else:
            verdict = "NO_ARTIFACTS"

        data = {
            "id": self.id,
            "product_id": self.product_id,
            "version": self.version,
            "release_date": self.release_date.isoformat() if self.release_date else None,
            "lifecycle_status": self.lifecycle_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "artifacts_count": len(artifacts_list),
            "tiers": tiers,
            "overall_verdict": verdict,
        }

        if include_artifacts:
            data["artifacts"] = [a.to_dict() for a in artifacts_list]

        return data


class SBOMArtifact(Base):
    """
    Represents an audited SBOM file linked to a specific system tier
    (OS, CONTAINER, APPLICATION, FIRMWARE) within a ProductRelease.
    """

    __tablename__ = "sbom_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    release_id = Column(
        Integer,
        ForeignKey("product_releases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tier = Column(String(50), nullable=False, default="APPLICATION", index=True)  # OS, CONTAINER, APPLICATION, FIRMWARE
    format = Column(String(50), nullable=False)  # cyclonedx, spdx
    spec_version = Column(String(50), nullable=True)  # 1.6, 1.7, 2.3, etc.
    file_path = Column(String(512), nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    sha512_hash = Column(String(128), nullable=True)
    overall_status = Column(String(50), nullable=False)  # PASS, FAIL, WARNING
    validation_report_id = Column(
        Integer,
        ForeignKey("validation_reports.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    sbom_record_id = Column(
        Integer,
        ForeignKey("sbom_records.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    release = relationship("ProductRelease", back_populates="artifacts")
    validation_report = relationship("ValidationReport", foreign_keys=[validation_report_id])
    sbom_record = relationship("SBOMRecord", foreign_keys=[sbom_record_id])

    def to_dict(self):
        return {
            "id": self.id,
            "release_id": self.release_id,
            "tier": self.tier,
            "format": self.format,
            "spec_version": self.spec_version,
            "file_path": self.file_path,
            "sha256_hash": self.sha256_hash,
            "sha512_hash": self.sha512_hash,
            "overall_status": self.overall_status,
            "validation_report_id": self.validation_report_id,
            "sbom_record_id": self.sbom_record_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
