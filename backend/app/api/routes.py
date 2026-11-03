"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
API Routes for ENISA Technical Advisory (October 2026) & EU CRA Compliance Auditing.
"""

import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

try:
    import orjson
except ImportError:
    orjson = None

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.auth_hook import require_role
from app.core.config import settings
from app.core.database import get_db
from app.core.enisa_engine import audit_enisa_compliance
from app.models.sbom import SBOMRecord, ValidationReport
from app.utils.report_generator import ReportGenerator

logger = logging.getLogger("regubom.api")
router = APIRouter(prefix="/api", tags=["regulatory-sbom"])

ALLOWED_EXTENSIONS = {".json", ".cdx", ".spdx"}
EXCEL_MIMES = {
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
EXCEL_EXTENSIONS = {".xlsx", ".xls"}
INVALID_FORMAT_DETAIL = (
    "Invalid file format detected. Only CycloneDX JSON (v1.6/v1.7) and SPDX JSON (v2.3/v3.0.1) are accepted. "
    "Unstructured binary, text, or spreadsheet files are rejected."
)


def _compute_imprint(content: bytes, file_size: int) -> dict:
    """Calculates cryptographic file imprints (SHA-256 and SHA-512) and sizes."""
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha512": hashlib.sha512(content).hexdigest(),
        "file_size_mb": round(file_size / (1024 * 1024), 2),
        "file_size_bytes": file_size,
    }


def _parse_sbom_bytes(content: bytes) -> dict:
    """Parses JSON bytes with orjson fallback to standard library."""
    if orjson is not None:
        try:
            return orjson.loads(content)
        except Exception:
            pass
    return json.loads(content.decode("utf-8", errors="replace"))


def _write_file_bytes(file_path: Path, data: bytes) -> None:
    """Writes bytes to disk safely."""
    with open(file_path, "wb") as f:
        f.write(data)


@router.post(
    "/validate",
    summary="Audit SBOM against ENISA October 2026 Advisory & EU CRA Article 13",
    description=(
        "Ingests CycloneDX (v1.6, v1.7 ECMA-424) or SPDX (v2.3, v3.0.1) JSON documents. "
        "Audits Table 1 document metadata, generates the 12-point ENISA/BSI regulatory checklist, "
        "and computes the 8-column Component Completeness Matrix with bifurcated 1st vs 3rd party logic."
    ),
    dependencies=[Depends(require_role(["admin", "operator"]))],
)
async def validate_sbom(
    file: UploadFile = File(...),
    max_size: int = Form(500),
    profile: str | None = Form("ENISA_2026"),
    proprietary_prefix: str | None = Form(None),
    proprietary_supplier: str | None = Form(None),
    db: Session = Depends(get_db),
):
    raw_filename = file.filename or "unknown"
    safe_filename = Path(raw_filename).name  # Defend against path traversal
    ext = Path(safe_filename).suffix.lower()
    raw_content_type = (file.content_type or "").lower().split(";")[0].strip()

    # Block non-compliant file types
    if (raw_content_type in EXCEL_MIMES) or (ext in EXCEL_EXTENSIONS):
        logger.warning(f"[Validate] Rejected Excel payload: '{safe_filename}'")
        raise HTTPException(status_code=400, detail=INVALID_FORMAT_DETAIL)

    content = await file.read()
    file_size = len(content)
    max_bytes = max_size * 1024 * 1024

    if file_size > max_bytes:
        logger.warning(f"[Validate] File exceeds maximum size: {file_size} > {max_bytes}")
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file exceeds limit ({file_size} bytes > {max_bytes} bytes allowed)",
        )

    # Magic byte signature pre-check (block PK zip archives and OLE headers)
    if content.startswith(b"PK\x03\x04") or content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        raise HTTPException(status_code=400, detail=INVALID_FORMAT_DETAIL)

    # Compute raw file cryptographic imprint
    file_imprint = await asyncio.to_thread(_compute_imprint, content, file_size)

    # Parse JSON
    try:
        sbom_data = await asyncio.to_thread(_parse_sbom_bytes, content)
    except Exception as e:
        logger.error(f"[Validate] Failed to parse JSON for '{safe_filename}': {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON document: {e}")

    if not isinstance(sbom_data, dict):
        raise HTTPException(status_code=400, detail="Root SBOM JSON payload must be an object.")

    # Save uploaded file
    file_id = str(uuid.uuid4())
    stored_filename = f"{file_id}_{safe_filename}"
    file_path = settings.UPLOAD_DIR / stored_filename
    await asyncio.to_thread(_write_file_bytes, file_path, content)

    # Effective tenant settings
    eff_prefix = proprietary_prefix or settings.DEFAULT_PROPRIETARY_PREFIX
    eff_supplier = proprietary_supplier or settings.DEFAULT_PROPRIETARY_SUPPLIER

    # Run ENISA Technical Advisory Compliance Engine in worker thread
    start_time = datetime.now(UTC)
    enisa_result = await asyncio.to_thread(
        audit_enisa_compliance,
        sbom_data,
        file_imprint=file_imprint,
        proprietary_prefix=eff_prefix,
        proprietary_supplier=eff_supplier,
    )
    elapsed = (datetime.now(UTC) - start_time).total_seconds()

    format_info = enisa_result["format_info"]
    sbom_format = format_info["format"]
    schema_version = format_info["version"]

    # Persist SBOMRecord
    sbom_record = SBOMRecord(
        filename=stored_filename,
        original_filename=safe_filename,
        file_size=file_size,
        file_path=str(file_path),
        sbom_format=sbom_format,
        schema_version=schema_version,
        sbom_data=sbom_data,
    )
    db.add(sbom_record)
    db.commit()
    db.refresh(sbom_record)

    # Prepare structured report payload
    report_data = {
        "filename": safe_filename,
        "format": sbom_format,
        "schema_version": schema_version,
        "profile": profile or "ENISA_2026",
        "overall_status": enisa_result["overall_status"],
        "overall_valid": enisa_result["overall_valid"],
        "processing_time": elapsed,
        "format_info": format_info,
        "document_metadata": enisa_result["document_metadata"],
        "root_product": enisa_result["root_product"],
        "root_product_name": enisa_result["root_product"].get("name", "N/D"),
        "root_product_version": enisa_result["root_product"].get("version", "N/D"),
        "file_imprint": file_imprint,
        "cra_checklist": enisa_result["cra_checklist"],
        "component_matrix": enisa_result["component_matrix"],
        "statistics": enisa_result["statistics"],
        "certificate_data": enisa_result["certificate_data"],
    }

    # Save report files to disk
    report_gen = ReportGenerator()
    json_report_path = settings.REPORT_DIR / f"report_{sbom_record.id}.json"
    html_report_path = settings.REPORT_DIR / f"report_{sbom_record.id}.html"
    pdf_report_path = settings.REPORT_DIR / f"report_{sbom_record.id}.pdf"
    cert_path = settings.REPORT_DIR / f"certificate_{sbom_record.id}.json"

    await asyncio.to_thread(report_gen.save_json_report, report_data, str(json_report_path))
    await asyncio.to_thread(report_gen.save_html_report, report_data, str(html_report_path))
    await asyncio.to_thread(report_gen.save_json_report, enisa_result["certificate_data"], str(cert_path))

    try:
        await asyncio.to_thread(report_gen.save_pdf_report, report_data, str(pdf_report_path))
    except Exception as e:
        logger.warning(f"[Validate] WeasyPrint PDF compilation bypassed: {e}")

    # Persist ValidationReport
    report_record = ValidationReport(
        sbom_id=sbom_record.id,
        report_filename=f"report_{sbom_record.id}.json",
        report_path=str(json_report_path),
        overall_status=enisa_result["overall_status"],
        overall_valid=enisa_result["overall_valid"],
        processing_time=elapsed,
        report_data=report_data,
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    return {
        "sbom_id": sbom_record.id,
        "report_id": report_record.id,
        "filename": safe_filename,
        "format": sbom_format,
        "schema_version": schema_version,
        "profile": profile,
        "overall_status": enisa_result["overall_status"],
        "overall_valid": enisa_result["overall_valid"],
        "processing_time": elapsed,
        "format_info": format_info,
        "document_metadata": enisa_result["document_metadata"],
        "root_product": enisa_result["root_product"],
        "file_imprint": file_imprint,
        "cra_checklist": enisa_result["cra_checklist"],
        "component_matrix": enisa_result["component_matrix"],
        "statistics": enisa_result["statistics"],
        "certificate_data": enisa_result["certificate_data"],
        "report_urls": {
            "json": f"/api/reports/{report_record.id}/download/json",
            "html": f"/api/reports/{report_record.id}/download/html",
            "pdf": f"/api/reports/{report_record.id}/download/pdf",
            "certificate": f"/api/reports/{report_record.id}/certificate",
        },
    }


@router.get(
    "/reports/{report_id}/certificate",
    summary="Download JSON Compliance Certificate",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def get_compliance_certificate(report_id: int, db: Session = Depends(get_db)):
    """Downloads Standalone JSON Compliance Certificate conforming to CRA Art. 13 & ENISA Advisory 2026."""
    report = db.query(ValidationReport).filter(ValidationReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Validation report not found.")

    cert_path = settings.REPORT_DIR / f"certificate_{report_id}.json"
    if cert_path.exists():
        return FileResponse(
            path=str(cert_path),
            filename=f"regubom_compliance_certificate_{report_id}.json",
            media_type="application/json",
        )

    cert_data = report.report_data.get("certificate_data") or report.report_data
    return JSONResponse(
        content=cert_data,
        headers={"Content-Disposition": f"attachment; filename=regubom_compliance_certificate_{report_id}.json"},
    )


@router.get(
    "/reports",
    summary="List historical validation reports",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def list_reports(
    limit: int = Query(50),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(ValidationReport).order_by(ValidationReport.validation_timestamp.desc())
    if status:
        query = query.filter(ValidationReport.overall_status == status.upper())
    reports = query.limit(limit).all()

    sbom_map = {}
    for r in reports:
        sbom = db.query(SBOMRecord).filter(SBOMRecord.id == r.sbom_id).first()
        sbom_map[r.sbom_id] = sbom

    return {
        "reports": [
            {
                "report_id": r.id,
                "sbom_id": r.sbom_id,
                "filename": sbom_map.get(r.sbom_id).original_filename if sbom_map.get(r.sbom_id) else "unknown",
                "format": sbom_map.get(r.sbom_id).sbom_format if sbom_map.get(r.sbom_id) else "unknown",
                "overall_status": r.overall_status,
                "overall_valid": r.overall_valid,
                "processing_time": r.processing_time,
                "validation_timestamp": r.validation_timestamp.isoformat() if r.validation_timestamp else None,
                "statistics": r.report_data.get("statistics", {}),
            }
            for r in reports
        ]
    }


@router.get(
    "/reports/{report_id}",
    summary="Get validation report details",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ValidationReport).filter(ValidationReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    sbom = db.query(SBOMRecord).filter(SBOMRecord.id == report.sbom_id).first()
    report_dict = dict(report.report_data or {})

    # Ensure ENISA checklist and matrix are refreshed if legacy format is stored
    if (
        "cra_checklist" not in report_dict
        or not report_dict.get("cra_checklist")
        or len(report_dict.get("cra_checklist", [])) < 12
    ):
        if sbom and sbom.sbom_data:
            enisa_res = audit_enisa_compliance(sbom.sbom_data, file_imprint=report_dict.get("file_imprint"))
            report_dict["cra_checklist"] = enisa_res["cra_checklist"]
            report_dict["component_matrix"] = enisa_res["component_matrix"]
            report_dict["statistics"] = enisa_res["statistics"]
            report_dict["format_info"] = enisa_res["format_info"]
            report_dict["document_metadata"] = enisa_res["document_metadata"]
            report_dict["certificate_data"] = enisa_res["certificate_data"]
            report.report_data = report_dict
            try:
                db.commit()
            except Exception:
                db.rollback()

    return {
        "report_id": report.id,
        "sbom_id": report.sbom_id,
        "filename": sbom.original_filename if sbom else "unknown",
        "format": sbom.sbom_format if sbom else "unknown",
        "schema_version": sbom.schema_version if sbom else "unknown",
        "overall_valid": report.overall_valid,
        "overall_status": report.overall_status,
        "processing_time": report.processing_time,
        "validation_timestamp": report.validation_timestamp.isoformat() if report.validation_timestamp else None,
        "report_data": report_dict,
    }


@router.get(
    "/reports/{report_id}/download/{fmt}",
    summary="Download report in specified format",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def download_report(report_id: int, fmt: str, db: Session = Depends(get_db)):
    report = db.query(ValidationReport).filter(ValidationReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    if fmt == "certificate":
        return await get_compliance_certificate(report_id, db=db)

    elif fmt == "json":
        file_path = settings.REPORT_DIR / f"report_{report_id}.json"
        if file_path.exists():
            return FileResponse(
                path=str(file_path),
                filename=f"regubom_report_{report_id}.json",
                media_type="application/json",
            )
        report_gen = ReportGenerator()
        return JSONResponse(content=report_gen.generate_json(report.report_data))

    elif fmt == "html":
        file_path = settings.REPORT_DIR / f"report_{report_id}.html"
        if file_path.exists():
            return FileResponse(
                path=str(file_path),
                filename=f"regubom_technical_dossier_{report_id}.html",
                media_type="text/html",
            )
        report_gen = ReportGenerator()
        return HTMLResponse(content=report_gen.generate_html(report.report_data))

    elif fmt == "pdf":
        file_path = settings.REPORT_DIR / f"report_{report_id}.pdf"
        if file_path.exists():
            return FileResponse(
                path=str(file_path),
                filename=f"regubom_technical_dossier_{report_id}.pdf",
                media_type="application/pdf",
            )
        report_gen = ReportGenerator()
        try:
            content = report_gen.generate_pdf(report.report_data)
            return Response(content=content, media_type="application/pdf")
        except Exception:
            # Fallback to printable HTML report
            html_content = report_gen.generate_html(report.report_data)
            return HTMLResponse(content=html_content)

    raise HTTPException(
        status_code=400,
        detail="Invalid format. Supported: json, html, pdf, certificate",
    )


@router.get(
    "/sboms/{sbom_id}/viewer",
    summary="Interactive SBOM Component & Gap Analysis",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def get_sbom_viewer(sbom_id: int, db: Session = Depends(get_db)):
    sbom = db.query(SBOMRecord).filter(SBOMRecord.id == sbom_id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM record not found.")

    sbom_dict = sbom.sbom_data
    if not sbom_dict and sbom.file_path:
        file_path = Path(sbom.file_path)
        if file_path.exists():
            try:
                raw_bytes = await asyncio.to_thread(file_path.read_bytes)
                sbom_dict = (
                    await asyncio.to_thread(orjson.loads, raw_bytes)
                    if orjson
                    else json.loads(raw_bytes.decode("utf-8", errors="replace"))
                )
            except Exception as e:
                logger.error(f"[Viewer] Failed reading SBOM file {file_path}: {e}")
                raise HTTPException(status_code=500, detail=f"Failed reading SBOM file: {e}")

    if not isinstance(sbom_dict, dict):
        raise HTTPException(status_code=400, detail="Invalid SBOM structured data.")

    # Run ENISA audit for interactive viewer
    enisa_res = await asyncio.to_thread(audit_enisa_compliance, sbom_dict)

    return {
        "sbom_id": sbom.id,
        "filename": sbom.original_filename or sbom.filename,
        "format": sbom.sbom_format,
        "schema_version": sbom.schema_version,
        "file_size": sbom.file_size,
        "upload_timestamp": sbom.upload_timestamp.isoformat() if sbom.upload_timestamp else None,
        "format_info": enisa_res["format_info"],
        "document_metadata": enisa_res["document_metadata"],
        "root_product": enisa_res["root_product"],
        "statistics": enisa_res["statistics"],
        "cra_checklist": enisa_res["cra_checklist"],
        "component_matrix": enisa_res["component_matrix"],
    }


@router.get(
    "/reports/{report_id}/viewer",
    summary="Viewer alias by report ID",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def get_report_viewer(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ValidationReport).filter(ValidationReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return await get_sbom_viewer(report.sbom_id, db=db)


@router.get(
    "/sboms/{sbom_id}",
    summary="Get raw original SBOM content",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def get_sbom(sbom_id: int, db: Session = Depends(get_db)):
    sbom = db.query(SBOMRecord).filter(SBOMRecord.id == sbom_id).first()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found.")
    return {
        "sbom_id": sbom.id,
        "filename": sbom.original_filename,
        "format": sbom.sbom_format,
        "schema_version": sbom.schema_version,
        "file_size": sbom.file_size,
        "upload_timestamp": sbom.upload_timestamp.isoformat() if sbom.upload_timestamp else None,
        "sbom_data": sbom.sbom_data,
    }


@router.get(
    "/sboms",
    summary="List all uploaded SBOM files",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def list_sboms(limit: int = Query(50), db: Session = Depends(get_db)):
    sboms = db.query(SBOMRecord).order_by(SBOMRecord.upload_timestamp.desc()).limit(limit).all()
    return {"sboms": [s.to_dict() for s in sboms]}


@router.delete(
    "/reports/{report_id}",
    summary="Delete report and associated SBOM",
    dependencies=[Depends(require_role(["admin", "operator"]))],
)
async def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ValidationReport).filter(ValidationReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    sbom = db.query(SBOMRecord).filter(SBOMRecord.id == report.sbom_id).first()

    for ext in ["json", "html", "pdf"]:
        p = settings.REPORT_DIR / f"report_{report_id}.{ext}"
        if p.exists():
            os.remove(p)
    cert_p = settings.REPORT_DIR / f"certificate_{report_id}.json"
    if cert_p.exists():
        os.remove(cert_p)

    if sbom and Path(sbom.file_path).exists():
        os.remove(sbom.file_path)

    db.delete(report)
    if sbom:
        db.delete(sbom)
    db.commit()

    return {"message": "Report and SBOM successfully deleted."}


@router.get(
    "/stats",
    summary="Aggregate dashboard metrics",
    dependencies=[Depends(require_role(["auditor"]))],
)
async def get_stats(db: Session = Depends(get_db)):
    total = db.query(ValidationReport).count()
    passed = db.query(ValidationReport).filter(ValidationReport.overall_valid == True).count()
    failed = db.query(ValidationReport).filter(ValidationReport.overall_valid == False).count()
    last = db.query(ValidationReport).order_by(ValidationReport.validation_timestamp.desc()).first()
    sbom_count = db.query(SBOMRecord).count()

    return {
        "total_validations": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round((passed / total * 100), 1) if total > 0 else 0,
        "total_sboms": sbom_count,
        "last_validation": last.validation_timestamp.isoformat() if last and last.validation_timestamp else None,
    }


@router.get("/health", summary="Health check endpoint")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
    }
