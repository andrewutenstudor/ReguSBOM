# Local Docker Deployment for SBOM Validator

This directory contains the standalone Docker Compose deployment for running the enterprise SBOM Validator locally.

## Architecture

- **Backend**: FastAPI + Python 3.12 (port `8000`), with persistent volumes for SQLite, uploads, and reports.
- **Frontend**: React + Vite + Nginx (port `5173`), reverse-proxying API calls to the backend with 300s timeouts.

## Quick Start

### 1. Start the containers
From the project root:
```bash
docker compose up -d --build
```
Or from within the `docker/` folder:
```bash
docker compose -f docker-compose.yml up -d --build
```

### 2. Access the Application
- **Web UI**: [http://localhost:5173](http://localhost:5173)
- **FastAPI Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

### 3. Inspect Logs
```bash
docker logs -f sbom-validator-backend
docker logs -f sbom-validator-frontend
```

### 4. Stop the containers
```bash
docker compose down
```
To also remove persistent volumes:
```bash
docker compose down -v
```
