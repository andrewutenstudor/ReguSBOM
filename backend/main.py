"""Entrypoint module for SBOM Validator backend.

Delegates to the main FastAPI application defined in app.main.
Allows running with either:
    uvicorn main:app --host 0.0.0.0 --port 8000
or:
    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from app.main import app

__all__ = ["app"]