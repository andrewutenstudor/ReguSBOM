"""
Database session management for ReguBOM.
Ensures SQLAlchemy uses pool_pre_ping=True for resilient PostgreSQL connectivity
and provides chunked bulk insertion for high-throughput SBOM ingestion.
"""

from app.core.database import (
    Base,
    SessionLocal,
    chunked_bulk_insert,
    engine,
    get_db,
    init_db,
)

__all__ = ["Base", "SessionLocal", "chunked_bulk_insert", "engine", "get_db", "init_db"]
