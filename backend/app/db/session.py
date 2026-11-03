"""
Database session management for ReguBOM.
Ensures SQLAlchemy uses pool_pre_ping=True for resilient PostgreSQL connectivity
and provides chunked bulk insertion for high-throughput SBOM ingestion.
"""
from app.core.database import engine, SessionLocal, Base, get_db, init_db, chunked_bulk_insert

__all__ = ["engine", "SessionLocal", "Base", "get_db", "init_db", "chunked_bulk_insert"]
