"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
API Routes for Product & Release Asset Catalog.
Hierarchical structure: Product -> ProductRelease -> SBOMArtifact (OS, CONTAINER, APPLICATION, FIRMWARE).
Integrates directly with the ENISA October 2026 / CRA Article 13 Compliance Engine.
"""
import asyncio
import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from app.core.config import settings
from app.core.database import get_db
from app.core.enisa_engine import audit_enisa_compliance
from app.core.diff_engine import compare_sboms
from app.core.auth import Role, require_role, get_current_user
from app.models.catalog import Product, ProductRelease, SBOMArtifact
from app.models.sbom import SBOMRecord, ValidationReport
from app.api.routes import _compute_imprint, _parse_sbom_bytes, _write_file_bytes, ALLOWED_EXTENSIONS, EXCEL_MIMES, EXCEL_EXTENSIONS, INVALID_FORMAT_DETAIL

logger = logging.getLogger("regubom.catalog")
router = APIRouter(prefix="/api", tags=["product-catalog"])

VALID_TIERS = {"OS", "CONTAINER", "APPLICATION", "FIRMWARE"}
VALID_LIFECYCLES = {"DRAFT", "VALIDATED", "RELEASED", "EOL"}


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------
class ProductCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Product Name")
    slug: Optional[str] = Field(None, max_length=255, description="URL-friendly identifier")
    description: Optional[str] = Field(None, description="Detailed product description")
    business_unit: Optional[str] = Field(None, max_length=255, description="Business Unit / Division")


class ProductUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    business_unit: Optional[str] = None


class ReleaseCreateRequest(BaseModel):
    version: str = Field(..., min_length=1, max_length=100, description="Release version, e.g. 'v2.1.0'")
    release_date: Optional[datetime] = Field(None, description="Official release date")
    lifecycle_status: Optional[str] = Field("DRAFT", description="DRAFT, VALIDATED, RELEASED, or EOL")


class ReleaseUpdateRequest(BaseModel):
    lifecycle_status: Optional[str] = Field(None, description="DRAFT, VALIDATED, RELEASED, or EOL")
    release_date: Optional[datetime] = None


def _slugify(text: str) -> str:
    """Generates a clean URL slug from a name."""
    s = text.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_-]+", "-", s)
    return s.strip("-") or "product"


# ---------------------------------------------------------------------------
# 1. Product Management
# ---------------------------------------------------------------------------
@router.post(
    "/products",
    status_code=status.HTTP_201_CREATED,
    summary="Create a new Product in the Catalog",
    dependencies=[Depends(require_role([Role.ADMIN, Role.RELEASE_MANAGER]))]
)
async def create_product(
    payload: ProductCreateRequest,
    db: Session = Depends(get_db)
):
    """Registers a new Product asset in the ReguBOM catalog."""
    raw_slug = payload.slug.strip() if payload.slug else _slugify(payload.name)
    slug = _slugify(raw_slug)

    # Ensure uniqueness of slug
    existing = db.query(Product).filter(Product.slug == slug).first()
    if existing:
        slug = f"{slug}-{uuid.uuid4().hex[:6]}"

    product = Product(
        name=payload.name.strip(),
        slug=slug,
        description=payload.description.strip() if payload.description else None,
        business_unit=payload.business_unit.strip() if payload.business_unit else None,
        created_at=datetime.utcnow()
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    logger.info(f"[Catalog] Created product: {product.name} (id={product.id}, slug={product.slug})")
    return product.to_dict(include_releases=True)


@router.get(
    "/products",
    summary="List all Products with aggregated compliance and release metrics"
)
async def list_products(
    search: Optional[str] = Query(None, description="Search by name or slug"),
    business_unit: Optional[str] = Query(None, description="Filter by business unit"),
    db: Session = Depends(get_db)
):
    """Lists products with summary metrics (release count, latest status, latest verdict)."""
    query = db.query(Product)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(or_(Product.name.ilike(s), Product.slug.ilike(s)))
    if business_unit:
        query = query.filter(Product.business_unit == business_unit.strip())

    products = query.order_by(desc(Product.created_at)).all()
    return [p.to_dict(include_releases=False) for p in products]


@router.get(
    "/products/{product_ref}",
    summary="Get Product details with complete Release & System Tier hierarchy"
)
async def get_product(
    product_ref: str,
    db: Session = Depends(get_db)
):
    """Retrieves a single product by numeric ID or slug with its full release tree."""
    product = None
    if product_ref.isdigit():
        product = db.query(Product).filter(Product.id == int(product_ref)).first()
    if not product:
        product = db.query(Product).filter(Product.slug == product_ref).first()

    if not product:
        raise HTTPException(status_code=404, detail=f"Product '{product_ref}' not found.")

    return product.to_dict(include_releases=True)


@router.delete(
    "/products/{product_ref}",
    summary="Delete Product and cascade all releases and artifacts",
    dependencies=[Depends(require_role([Role.ADMIN]))]
)
async def delete_product(
    product_ref: str,
    db: Session = Depends(get_db)
):
    """Deletes a product and all its child releases and SBOM artifacts."""
    product = None
    if product_ref.isdigit():
        product = db.query(Product).filter(Product.id == int(product_ref)).first()
    if not product:
        product = db.query(Product).filter(Product.slug == product_ref).first()

    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    db.delete(product)
    db.commit()
    return {"message": f"Product '{product.name}' and all associated assets deleted successfully."}


# ---------------------------------------------------------------------------
# 2. Release Management
# ---------------------------------------------------------------------------
@router.post(
    "/products/{product_ref}/releases",
    status_code=status.HTTP_201_CREATED,
    summary="Register a Release Version for a Product",
    dependencies=[Depends(require_role([Role.ADMIN, Role.RELEASE_MANAGER]))]
)
async def create_release(
    product_ref: str,
    payload: ReleaseCreateRequest,
    db: Session = Depends(get_db)
):
    """Registers a release version (e.g. 'v2.1.0') under the designated product."""
    product = None
    if product_ref.isdigit():
        product = db.query(Product).filter(Product.id == int(product_ref)).first()
    if not product:
        product = db.query(Product).filter(Product.slug == product_ref).first()

    if not product:
        raise HTTPException(status_code=404, detail=f"Product '{product_ref}' not found.")

    clean_version = payload.version.strip()
    status_val = payload.lifecycle_status.upper() if payload.lifecycle_status else "DRAFT"
    if status_val not in VALID_LIFECYCLES:
        raise HTTPException(status_code=400, detail=f"Invalid lifecycle_status. Must be one of: {VALID_LIFECYCLES}")

    # Check for existing release
    existing = db.query(ProductRelease).filter(
        ProductRelease.product_id == product.id,
        ProductRelease.version == clean_version
    ).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Release '{clean_version}' already exists for product '{product.name}'."
        )

    release = ProductRelease(
        product_id=product.id,
        version=clean_version,
        release_date=payload.release_date or datetime.utcnow(),
        lifecycle_status=status_val,
        created_at=datetime.utcnow()
    )
    db.add(release)
    db.commit()
    db.refresh(release)
    logger.info(f"[Catalog] Registered release {release.version} for product {product.name}")
    return release.to_dict(include_artifacts=True)


@router.patch(
    "/products/{product_ref}/releases/{release_id}",
    summary="Update Release lifecycle status or release date",
    dependencies=[Depends(require_role([Role.ADMIN, Role.RELEASE_MANAGER]))]
)
async def update_release(
    product_ref: str,
    release_id: int,
    payload: ReleaseUpdateRequest,
    db: Session = Depends(get_db)
):
    """Updates lifecycle status (DRAFT, VALIDATED, RELEASED, EOL) of a release."""
    release = db.query(ProductRelease).filter(ProductRelease.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found.")

    if payload.lifecycle_status:
        st = payload.lifecycle_status.upper()
        if st not in VALID_LIFECYCLES:
            raise HTTPException(status_code=400, detail=f"Invalid lifecycle_status. Must be one of: {VALID_LIFECYCLES}")
        release.lifecycle_status = st

    if payload.release_date:
        release.release_date = payload.release_date

    db.commit()
    db.refresh(release)
    return release.to_dict(include_artifacts=True)


@router.delete(
    "/products/{product_ref}/releases/{release_id}",
    summary="Delete a Release and its child SBOM artifacts",
    dependencies=[Depends(require_role([Role.ADMIN, Role.RELEASE_MANAGER]))]
)
async def delete_release(
    product_ref: str,
    release_id: int,
    db: Session = Depends(get_db)
):
    """Deletes a release and all of its tier artifacts."""
    release = db.query(ProductRelease).filter(ProductRelease.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found.")

    db.delete(release)
    db.commit()
    return {"message": f"Release '{release.version}' deleted successfully."}


# ---------------------------------------------------------------------------
# 3. SBOM Ingestion into Product Hierarchy (with ENISA Audit Engine)
# ---------------------------------------------------------------------------
@router.post(
    "/products/{product_ref}/releases/{version}/upload",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and Audit SBOM into Product Release Hierarchy",
    dependencies=[Depends(require_role([Role.ADMIN, Role.RELEASE_MANAGER, Role.DEVELOPER]))]
)
async def upload_sbom_to_release(
    product_ref: str,
    version: str,
    file: UploadFile = File(...),
    tier: str = Form("APPLICATION"),
    proprietary_prefix: Optional[str] = Form(None),
    proprietary_supplier: Optional[str] = Form(None),
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Ingests an SBOM file directly into a Product Release at a specific system tier
    (OS, CONTAINER, APPLICATION, FIRMWARE). Automatically executes the full ENISA
    October 2026 / CRA Article 13 compliance audit and registers the artifact.
    Enforces least-privilege scoping on machine API tokens.
    """
    # 1. Resolve Product
    product = None
    if product_ref.isdigit():
        product = db.query(Product).filter(Product.id == int(product_ref)).first()
    if not product:
        product = db.query(Product).filter(Product.slug == product_ref).first()

    if not product:
        raise HTTPException(status_code=404, detail=f"Product '{product_ref}' not found.")

    # 1b. Scoped API Key least-privilege verification
    allowed_prods = getattr(current_user, "allowed_products", ["*"]) or ["*"]
    if "*" not in allowed_prods and product.slug not in allowed_prods:
        logger.warning(
            f"[RBAC Scope] Caller '{getattr(current_user, 'username', 'machine')}' "
            f"denied access to product '{product.slug}' (allowed products: {allowed_prods})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token not authorized for product '{product.slug}'",
        )

    # 2. Resolve or Auto-create Release
    clean_version = version.strip()
    release = db.query(ProductRelease).filter(
        ProductRelease.product_id == product.id,
        ProductRelease.version == clean_version
    ).first()

    if not release:
        # Auto-create release if not already present
        release = ProductRelease(
            product_id=product.id,
            version=clean_version,
            release_date=datetime.utcnow(),
            lifecycle_status="DRAFT",
            created_at=datetime.utcnow()
        )
        db.add(release)
        db.commit()
        db.refresh(release)
        logger.info(f"[Catalog] Auto-created release '{clean_version}' for product '{product.name}'")

    # 3. Validate Tier
    clean_tier = tier.upper().strip()
    if clean_tier not in VALID_TIERS:
        raise HTTPException(status_code=400, detail=f"Invalid tier '{tier}'. Must be one of: {sorted(list(VALID_TIERS))}")

    # 4. File Sanitization and Format Validation
    raw_filename = file.filename or "unknown"
    safe_filename = Path(raw_filename).name
    ext = Path(safe_filename).suffix.lower()
    raw_content_type = (file.content_type or "").lower().split(";")[0].strip()

    if (raw_content_type in EXCEL_MIMES) or (ext in EXCEL_EXTENSIONS):
        raise HTTPException(status_code=400, detail=INVALID_FORMAT_DETAIL)

    content = await file.read()
    file_size = len(content)
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024

    if file_size > max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum size ({file_size} > {max_bytes} bytes).")

    if content.startswith(b"PK\x03\x04") or content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        raise HTTPException(status_code=400, detail=INVALID_FORMAT_DETAIL)

    # 5. Compute Hashes
    file_imprint = await asyncio.to_thread(_compute_imprint, content, file_size)

    # 6. Parse JSON Content
    try:
        sbom_data = await asyncio.to_thread(_parse_sbom_bytes, content)
    except Exception as e:
        logger.error(f"[Catalog] Failed to parse SBOM JSON for '{safe_filename}': {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON document: {e}")

    if not isinstance(sbom_data, dict):
        raise HTTPException(status_code=400, detail="Root SBOM JSON payload must be an object.")

    # 7. Write File to Storage
    file_id = str(uuid.uuid4())
    stored_filename = f"{product.slug}_{clean_version}_{clean_tier}_{file_id[:8]}_{safe_filename}"
    file_path = settings.UPLOAD_DIR / stored_filename
    await asyncio.to_thread(_write_file_bytes, file_path, content)

    # 8. Run ENISA October 2026 Audit Engine
    eff_prefix = proprietary_prefix or settings.DEFAULT_PROPRIETARY_PREFIX
    eff_supplier = proprietary_supplier or product.name or settings.DEFAULT_PROPRIETARY_SUPPLIER

    start_time = datetime.now(timezone.utc)
    enisa_result = await asyncio.to_thread(
        audit_enisa_compliance,
        sbom_data,
        file_imprint=file_imprint,
        proprietary_prefix=eff_prefix,
        proprietary_supplier=eff_supplier
    )
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    format_info = enisa_result["format_info"]
    sbom_format = format_info["format"]
    schema_version = format_info["version"]
    overall_status = enisa_result["overall_status"]

    # 9. Persist SBOMRecord
    sbom_record = SBOMRecord(
        filename=stored_filename,
        original_filename=safe_filename,
        file_size=file_size,
        file_path=str(file_path),
        sbom_format=sbom_format,
        schema_version=schema_version,
        sbom_data=sbom_data
    )
    db.add(sbom_record)
    db.commit()
    db.refresh(sbom_record)

    # 10. Persist ValidationReport
    report_data = {
        "filename": safe_filename,
        "format": sbom_format,
        "schema_version": schema_version,
        "profile": "ENISA_2026",
        "overall_status": overall_status,
        "overall_valid": enisa_result["overall_valid"],
        "processing_time": elapsed,
        "format_info": format_info,
        "document_metadata": enisa_result["document_metadata"],
        "root_product": enisa_result["root_product"],
        "root_product_name": product.name,
        "root_product_version": clean_version,
        "file_imprint": file_imprint,
        "cra_checklist": enisa_result["cra_checklist"],
        "component_matrix": enisa_result["component_matrix"],
        "statistics": enisa_result["statistics"],
        "certificate_data": enisa_result.get("certificate_data", {}),
        "product_id": product.id,
        "release_id": release.id,
        "tier": clean_tier,
    }

    report_filename = f"report_catalog_{product.slug}_{clean_version}_{clean_tier}_{file_id[:8]}.json"
    report_path = settings.REPORT_DIR / report_filename
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    validation_report = ValidationReport(
        sbom_id=sbom_record.id,
        report_filename=report_filename,
        report_path=str(report_path),
        overall_status=overall_status,
        overall_valid=enisa_result["overall_valid"],
        processing_time=elapsed,
        report_data=report_data
    )
    db.add(validation_report)
    db.commit()
    db.refresh(validation_report)

    # 11. Persist SBOMArtifact
    artifact = SBOMArtifact(
        release_id=release.id,
        tier=clean_tier,
        format=sbom_format,
        spec_version=schema_version,
        file_path=str(file_path),
        sha256_hash=file_imprint["sha256"],
        sha512_hash=file_imprint["sha512"],
        overall_status=overall_status,
        validation_report_id=validation_report.id,
        sbom_record_id=sbom_record.id,
        created_at=datetime.utcnow()
    )
    db.add(artifact)

    # 12. Update Release Lifecycle Status if validated
    if release.lifecycle_status == "DRAFT" and overall_status in ("PASS", "WARNING"):
        release.lifecycle_status = "VALIDATED"

    db.commit()
    db.refresh(artifact)
    db.refresh(release)

    logger.info(
        f"[Catalog] Successfully ingested SBOM for product '{product.name}', "
        f"release '{clean_version}', tier '{clean_tier}': status={overall_status}"
    )

    return {
        "message": "SBOM successfully ingested and audited in Product Catalog.",
        "product": {
            "id": product.id,
            "name": product.name,
            "slug": product.slug,
        },
        "release": {
            "id": release.id,
            "version": release.version,
            "lifecycle_status": release.lifecycle_status,
        },
        "artifact": artifact.to_dict(),
        "validation_report_id": validation_report.id,
        "overall_status": overall_status,
        "statistics": enisa_result["statistics"],
        "checklist_summary": {
            "total": len(enisa_result["cra_checklist"]),
            "passed": sum(1 for item in enisa_result["cra_checklist"] if item["status"] == "PASS"),
            "warning": sum(1 for item in enisa_result["cra_checklist"] if item["status"] == "WARNING"),
            "fail": sum(1 for item in enisa_result["cra_checklist"] if item["status"] == "FAIL"),
        },
        "report_url": f"/reports/{validation_report.id}",
    }


# ---------------------------------------------------------------------------
# 4. Global Cross-Catalog Component Search
# ---------------------------------------------------------------------------
@router.get(
    "/catalog/search-component",
    summary="Global Component Search across all Products, Releases, and Tiers"
)
async def search_component_in_catalog(
    name: str = Query(..., min_length=1, description="Component library name to search"),
    version: Optional[str] = Query(None, description="Optional component version filter"),
    db: Session = Depends(get_db)
):
    """
    Scans all audited SBOM artifacts across all products and releases to find
    where a specific component library (e.g. 'log4j', 'openssl', 'axios') is deployed.
    Returns matched products, versions, tiers, and quick links to the 8-column matrix.
    """
    search_name = name.strip().lower()
    search_ver = version.strip().lower() if version else None

    # Load all artifacts with related product and release
    artifacts = (
        db.query(SBOMArtifact)
        .join(ProductRelease, SBOMArtifact.release_id == ProductRelease.id)
        .join(Product, ProductRelease.product_id == Product.id)
        .order_by(desc(SBOMArtifact.created_at))
        .all()
    )

    matches = []
    seen_keys = set()

    for artifact in artifacts:
        release = artifact.release
        if not release:
            continue
        product = release.product
        if not product:
            continue

        report = artifact.validation_report
        components = []

        if report and isinstance(report.report_data, dict):
            components = report.report_data.get("component_matrix", [])
        elif artifact.sbom_record and isinstance(artifact.sbom_record.sbom_data, dict):
            # Fallback to raw components array
            components = artifact.sbom_record.sbom_data.get("components", [])

        for comp in components:
            comp_name = str(comp.get("name", "")).strip()
            comp_ver = str(comp.get("version", "")).strip()

            # Case-insensitive substring match on component name
            if search_name in comp_name.lower():
                # If version is supplied, check match
                if search_ver and search_ver not in comp_ver.lower():
                    continue

                dedup_key = (product.id, release.id, artifact.tier, comp_name.lower(), comp_ver.lower())
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                matches.append({
                    "product_id": product.id,
                    "product_name": product.name,
                    "product_slug": product.slug,
                    "business_unit": product.business_unit,
                    "release_id": release.id,
                    "release_version": release.version,
                    "release_status": release.lifecycle_status,
                    "tier": artifact.tier,
                    "artifact_id": artifact.id,
                    "artifact_status": artifact.overall_status,
                    "validation_report_id": artifact.validation_report_id,
                    "component": {
                        "name": comp_name,
                        "version": comp_ver,
                        "supplier": comp.get("supplier", "N/D"),
                        "license": comp.get("license") or (comp.get("licenses", ["N/D"])[0] if isinstance(comp.get("licenses"), list) and comp.get("licenses") else "N/D"),
                        "purl": comp.get("purl"),
                        "cpe": comp.get("cpe"),
                        "is_proprietary": comp.get("is_proprietary", False),
                        "has_hash": comp.get("has_hash", "✕"),
                        "has_license": comp.get("has_license", "✕"),
                        "has_dependencies": comp.get("has_dependencies", "✕"),
                    }
                })

    return {
        "query": {
            "name": name,
            "version": version
        },
        "total_matches": len(matches),
        "matches": matches
    }


# ---------------------------------------------------------------------------
# 5. SBOM Differential & Drift Engine Endpoints
# ---------------------------------------------------------------------------
def _resolve_sbom_data_and_meta(identifier: int, db: Session) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Resolves an SBOM JSON payload and descriptor metadata from:
    1. SBOMArtifact ID
    2. ValidationReport ID
    3. SBOMRecord ID
    """
    # 1. Check SBOMArtifact
    artifact = db.query(SBOMArtifact).filter(SBOMArtifact.id == identifier).first()
    if artifact:
        # Load from sbom_record or file
        sbom_dict = None
        if artifact.sbom_record and isinstance(artifact.sbom_record.sbom_data, dict):
            sbom_dict = artifact.sbom_record.sbom_data
        elif Path(artifact.file_path).exists():
            with open(artifact.file_path, "r", encoding="utf-8") as f:
                sbom_dict = json.load(f)

        if not sbom_dict:
            raise HTTPException(status_code=404, detail=f"SBOM payload missing for artifact ID {identifier}")

        prod_name = artifact.release.product.name if artifact.release and artifact.release.product else "N/D"
        rel_ver = artifact.release.version if artifact.release else "N/D"

        meta = {
            "id": artifact.id,
            "type": "artifact",
            "label": f"{prod_name} — {rel_ver} [{artifact.tier}]",
            "product_name": prod_name,
            "release_version": rel_ver,
            "tier": artifact.tier,
            "format": artifact.format,
            "spec_version": artifact.spec_version,
            "sha256": artifact.sha256_hash,
            "overall_status": artifact.overall_status,
            "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
        }
        return sbom_dict, meta

    # 2. Check ValidationReport
    report = db.query(ValidationReport).filter(ValidationReport.id == identifier).first()
    if report:
        sbom_dict = None
        sbom_record = db.query(SBOMRecord).filter(SBOMRecord.id == report.sbom_id).first()
        if sbom_record and isinstance(sbom_record.sbom_data, dict):
            sbom_dict = sbom_record.sbom_data
        elif Path(report.report_path).exists():
            with open(report.report_path, "r", encoding="utf-8") as f:
                sbom_dict = json.load(f)

        if not sbom_dict:
            raise HTTPException(status_code=404, detail=f"SBOM payload missing for report ID {identifier}")

        meta = {
            "id": report.id,
            "type": "report",
            "label": f"Report #{report.id} — {report.report_filename}",
            "filename": report.report_filename,
            "overall_status": report.overall_status,
            "created_at": report.validation_timestamp.isoformat() if report.validation_timestamp else None,
        }
        return sbom_dict, meta

    # 3. Check SBOMRecord
    sbom_rec = db.query(SBOMRecord).filter(SBOMRecord.id == identifier).first()
    if sbom_rec:
        if not isinstance(sbom_rec.sbom_data, dict):
            if Path(sbom_rec.file_path).exists():
                with open(sbom_rec.file_path, "r", encoding="utf-8") as f:
                    sbom_rec.sbom_data = json.load(f)
            else:
                raise HTTPException(status_code=404, detail=f"SBOM file content missing for record ID {identifier}")

        meta = {
            "id": sbom_rec.id,
            "type": "sbom_record",
            "label": f"SBOM #{sbom_rec.id} — {sbom_rec.original_filename}",
            "filename": sbom_rec.original_filename,
            "format": sbom_rec.sbom_format,
            "spec_version": sbom_rec.schema_version,
            "created_at": sbom_rec.upload_timestamp.isoformat() if sbom_rec.upload_timestamp else None,
        }
        return sbom_rec.sbom_data, meta

    raise HTTPException(status_code=404, detail=f"Resource ID {identifier} not found as Artifact, Report, or SBOM.")


@router.get(
    "/diff",
    summary="Compute semantic differential and drift between two SBOM documents"
)
async def get_sbom_diff(
    base_id: int = Query(..., description="ID of Base SBOM (Artifact, Report, or SBOM ID)"),
    target_id: int = Query(..., description="ID of Target SBOM (Artifact, Report, or SBOM ID)"),
    db: Session = Depends(get_db)
):
    """
    Computes a deep semantic differential between Base (A) and Target (B) SBOMs.
    Identifies:
    - Added components
    - Removed components
    - Modified components (version upgrades, license changes, hash drops)
    - Dependency graph delta (added vs removed edges)
    - Executive compliance and security posture delta
    """
    base_data, base_meta = _resolve_sbom_data_and_meta(base_id, db)
    target_data, target_meta = _resolve_sbom_data_and_meta(target_id, db)

    delta = await asyncio.to_thread(compare_sboms, base_data, target_data)

    return {
        "base": base_meta,
        "target": target_meta,
        "summary": delta["summary"],
        "added_components": delta["added_components"],
        "removed_components": delta["removed_components"],
        "modified_components": delta["modified_components"],
        "dependency_graph_delta": delta["dependency_graph_delta"],
    }


@router.get(
    "/diff/candidates",
    summary="List available SBOMs and artifacts eligible for differential comparison"
)
async def list_diff_candidates(
    db: Session = Depends(get_db)
):
    """
    Returns all catalog artifacts and audited reports ready for dual-dropdown selection.
    """
    candidates = []

    # 1. Product Catalog Artifacts
    artifacts = (
        db.query(SBOMArtifact)
        .join(ProductRelease, SBOMArtifact.release_id == ProductRelease.id)
        .join(Product, ProductRelease.product_id == Product.id)
        .order_by(desc(SBOMArtifact.created_at))
        .all()
    )
    for a in artifacts:
        prod_name = a.release.product.name if a.release and a.release.product else "N/D"
        rel_ver = a.release.version if a.release else "N/D"
        candidates.append({
            "id": a.id,
            "type": "artifact",
            "category": "Product Catalog Tier",
            "label": f"📦 {prod_name} — {rel_ver} [{a.tier}] ({a.format.upper()} {a.spec_version or ''})",
            "product_name": prod_name,
            "release_version": rel_ver,
            "tier": a.tier,
            "status": a.overall_status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    # 2. Standalone Validation Reports
    reports = db.query(ValidationReport).order_by(desc(ValidationReport.validation_timestamp)).limit(50).all()
    for r in reports:
        # Check if already in candidates via artifact
        if not any(c.get("id") == r.id and c.get("type") == "report" for c in candidates):
            candidates.append({
                "id": r.id,
                "type": "report",
                "category": "Historical Dossier",
                "label": f"📋 Report #{r.id} — {r.report_filename} ({r.overall_status})",
                "filename": r.report_filename,
                "status": r.overall_status,
                "created_at": r.validation_timestamp.isoformat() if r.validation_timestamp else None,
            })

    return candidates


@router.get(
    "/products/{product_ref}/diff",
    summary="Compute differential drift between two product release versions"
)
async def get_product_release_diff(
    product_ref: str,
    base: str = Query(..., description="Base release version (e.g. 'v1.0.0')"),
    target: str = Query(..., description="Target release version (e.g. 'v1.1.0')"),
    tier: Optional[str] = Query(None, description="Optional system tier filter: OS, CONTAINER, APPLICATION, FIRMWARE"),
    db: Session = Depends(get_db)
):
    """
    Computes added, removed, and modified components between two cataloged releases of a product.
    Tracks metadata drift (dropped hashes, newly introduced non-SPDX licenses, severed graph edges).
    """
    product = None
    if product_ref.isdigit():
        product = db.query(Product).filter(Product.id == int(product_ref)).first()
    if not product:
        product = db.query(Product).filter(Product.slug == product_ref).first()

    if not product:
        raise HTTPException(status_code=404, detail=f"Product '{product_ref}' not found.")

    # Find base release
    base_rel = db.query(ProductRelease).filter(
        ProductRelease.product_id == product.id,
        ProductRelease.version == base.strip()
    ).first()
    if not base_rel:
        raise HTTPException(status_code=404, detail=f"Base release '{base}' not found for product '{product.name}'.")

    # Find target release
    target_rel = db.query(ProductRelease).filter(
        ProductRelease.product_id == product.id,
        ProductRelease.version == target.strip()
    ).first()
    if not target_rel:
        raise HTTPException(status_code=404, detail=f"Target release '{target}' not found for product '{product.name}'.")

    base_artifacts = base_rel.artifacts
    target_artifacts = target_rel.artifacts

    if tier:
        base_artifacts = [a for a in base_artifacts if a.tier.upper() == tier.upper()]
        target_artifacts = [a for a in target_artifacts if a.tier.upper() == tier.upper()]

    if not base_artifacts:
        raise HTTPException(status_code=404, detail=f"No artifacts found in base release '{base}'.")
    if not target_artifacts:
        raise HTTPException(status_code=404, detail=f"No artifacts found in target release '{target}'.")

    base_artifact = base_artifacts[0]
    target_artifact = target_artifacts[0]

    base_data, base_meta = _resolve_sbom_data_and_meta(base_artifact.id, db)
    target_data, target_meta = _resolve_sbom_data_and_meta(target_artifact.id, db)

    delta = await asyncio.to_thread(compare_sboms, base_data, target_data)

    return {
        "product": {
            "id": product.id,
            "name": product.name,
            "slug": product.slug,
        },
        "base_release": {
            "id": base_rel.id,
            "version": base_rel.version,
            "artifact_id": base_artifact.id,
            "tier": base_artifact.tier,
            "status": base_artifact.overall_status,
        },
        "target_release": {
            "id": target_rel.id,
            "version": target_rel.version,
            "artifact_id": target_artifact.id,
            "tier": target_artifact.tier,
            "status": target_artifact.overall_status,
        },
        "summary": delta["summary"],
        "added_components": delta["added_components"],
        "removed_components": delta["removed_components"],
        "modified_components": delta["modified_components"],
        "dependency_graph_delta": delta["dependency_graph_delta"],
    }


