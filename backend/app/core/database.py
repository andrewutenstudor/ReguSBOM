"""Database configuration and session management for ReguBOM."""
from typing import List, Dict, Any, Type
from sqlalchemy import create_engine, text, insert
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from app.core.config import settings

is_sqlite = settings.DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

db_url = settings.DATABASE_URL
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def chunked_bulk_insert(
    db: Session,
    model_class: Type[Any],
    records: List[Dict[str, Any]],
    chunk_size: int = 2000
) -> int:
    """
    High-Performance Chunked Insertion Helper.
    Prevents memory spikes and PostgreSQL query parameter limit crashes (65,535 params)
    when ingesting large SBOM component matrices (57,000+ items).
    Uses SQLAlchemy Core insert() executed in batches of chunk_size.
    """
    if not records:
        return 0

    total_inserted = 0
    for i in range(0, len(records), chunk_size):
        chunk = records[i : i + chunk_size]
        if chunk:
            db.execute(insert(model_class), chunk)
            db.commit()
            total_inserted += len(chunk)

    return total_inserted


def init_db():
    """Initialize Core Community Edition database tables (SBOMRecord, ValidationReport)."""
    from app.models.sbom import SBOMRecord, ValidationReport
    Base.metadata.create_all(bind=engine)
