"""
Main FastAPI application for ReguBOM — Regulatory SBOM Gateway.
Open-Core Architecture:
- Community Edition (CE): Open-Source (GNU AGPLv3) standalone SBOM validator and viewer.
- Enterprise Edition (EE): Commercial add-on loaded dynamically via ee.loader hook.
Compliant with EU Cyber Resilience Act (CRA Art. 13), ENISA Technical Advisory (October 2026),
BSI TR-03183-2 v2.1.0, and CISA 2026 Minimum Elements.
"""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as core_api_router
from app.core.config import settings
from app.core.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("regubom")

app = FastAPI(
    title=settings.APP_NAME,
    description="""
    ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway.
    Automated validation and compliance auditing for EU CRA Art. 13 & Annex II,
    ENISA Technical Advisory (October 2026), BSI TR-03183-2 v2.1.0, and CISA 2026 Minimum Elements.
    Supports CycloneDX (v1.6, v1.7 ECMA-424) and SPDX (v2.3, v3.0.1 ISO/IEC 5962:2021).
    """,
    version=settings.VERSION,
)

# Standard CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Register Core Open-Source API Routes (Community Edition)
app.include_router(core_api_router)

# Mount static asset directories
app.mount("/uploads", StaticFiles(directory=str(settings.UPLOAD_DIR)), name="uploads")
app.mount("/reports", StaticFiles(directory=str(settings.REPORT_DIR)), name="reports")

# 2. Dynamic Enterprise Edition Loader Hook
if os.getenv("REGUBOM_EDITION", "").lower() not in ("community", "ce"):
    try:
        from ee.loader import register_enterprise_extension

        register_enterprise_extension(app)
        logger.info("ReguBOM Enterprise Edition extension loaded successfully.")
    except (ImportError, ModuleNotFoundError):
        logger.info("ReguBOM Community Edition running (Open Source).")
else:
    logger.info("ReguBOM Community Edition running (Open Source).")


@app.on_event("startup")
async def startup_event():
    """Initialize Core Community Edition database tables on startup."""
    init_db()
    logger.info(f"ReguBOM core initialized using database: {settings.DATABASE_URL.split('://')[0]}")


@app.get("/health")
async def health_root():
    """Liveness probe endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
    }


@app.get("/")
async def root():
    """Root endpoint - returns ReguBOM Gateway metadata."""
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "standards": [
            "ENISA Technical Advisory on SBOM (October 2026)",
            "BSI TR-03183-2 v2.1.0",
            "CISA 2026 Minimum Elements",
            "EU Cyber Resilience Act (Regulation EU 2024/2847 Art. 13 & Annex II)",
        ],
        "accepted_formats": [
            "CycloneDX v1.6 (ECMA-424)",
            "CycloneDX v1.7 (ECMA-424)",
            "SPDX v2.3 (ISO/IEC 5962:2021)",
            "SPDX v3.0.1 (JSON-LD)",
        ],
    }
