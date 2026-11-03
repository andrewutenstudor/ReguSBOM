"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
License Management & Verification Endpoints.
Zero-telemetry offline license status inspection and upload.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.core.licensing import LicenseVerifier

logger = logging.getLogger("regubom.licensing.api")
router = APIRouter(prefix="/api/license", tags=["license-management"])


@router.get("", summary="Get active offline cryptographic license status")
@router.get("/status", summary="Get active offline cryptographic license status (alias)")
async def get_license_status():
    """
    Returns the current cryptographic license state, claims, customer identity,
    and remaining validity days without making any external network requests.
    """
    lic_status = LicenseVerifier.verify()
    return lic_status.to_dict()


@router.post(
    "/upload",
    status_code=status.HTTP_200_OK,
    summary="Upload a new signed offline license file",
)
async def upload_license(file: UploadFile = File(...)):
    """
    Installs a new Ed25519-signed offline license file (`license.lic`).
    Immediately verifies the cryptographic signature before accepting and activating.
    """
    filename = file.filename or "license.lic"
    if not (filename.endswith(".lic") or filename.endswith(".json")):
        raise HTTPException(
            status_code=400,
            detail="Invalid license file format. Must be a .lic or .json file.",
        )

    content = await file.read()
    temp_path = Path("license.lic.tmp")

    try:
        with open(temp_path, "wb") as f:
            f.write(content)

        # Verify the new candidate license
        test_status = LicenseVerifier.verify(license_file_path=temp_path, force_refresh=True)
        if not test_status.is_valid:
            if temp_path.exists():
                temp_path.unlink()
            raise HTTPException(
                status_code=400,
                detail=f"Uploaded license is invalid: {test_status.error_code} - {test_status.error_message}",
            )

        # Overwrite active license
        active_path = LicenseVerifier.find_license_file() or Path("license.lic")
        with open(active_path, "wb") as f:
            f.write(content)

        if temp_path.exists():
            temp_path.unlink()

        # Re-verify and refresh cache
        new_status = LicenseVerifier.verify(force_refresh=True)
        logger.info(f"[License] Successfully updated license for customer: {new_status.customer_name}")

        return {
            "message": "License successfully verified and activated.",
            "license": new_status.to_dict(),
        }
    except HTTPException:
        raise
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"[License] Error processing uploaded license: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process license file: {e}")
