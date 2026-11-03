"""Application configuration settings for ReguBOM."""
import os
from pathlib import Path


class Settings:
    """Application settings loaded from environment variables."""

    # Product identity
    APP_NAME = "ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway"
    VERSION = "2.0.0"

    # Base paths
    BASE_DIR = Path(__file__).resolve().parent.parent.parent
    UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(BASE_DIR / "uploads")))
    REPORT_DIR = Path(os.getenv("REPORT_DIR", str(BASE_DIR / "reports")))

    # Database: PostgreSQL with SQLite fallback
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sbom_validator.db")

    # File upload limits
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "500"))

    # CORS
    ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "*").split(",")]

    # Server
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8000"))

    # Configurable Tenant Settings for Proprietary Component Detection
    DEFAULT_PROPRIETARY_PREFIX = os.getenv("PROPRIETARY_PREFIX", "regubom:proprietary")
    DEFAULT_PROPRIETARY_SUPPLIER = os.getenv("PROPRIETARY_SUPPLIER", "")

    # CycloneDX & SPDX Standards
    SUPPORTED_CYCLONEDX_VERSIONS = ["1.6", "1.7"]
    SUPPORTED_SPDX_VERSIONS = ["2.3", "3.0.1"]

    def __init__(self):
        # Ensure directories exist
        self.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORT_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
