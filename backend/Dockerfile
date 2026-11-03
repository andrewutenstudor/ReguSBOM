FROM python:3.12-slim

# Install system dependencies (curl for healthchecks, libpq for PostgreSQL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Non-root user with explicit UID/GID 10001 for strict enterprise container security (OpenShift / RKE2)
RUN groupadd -g 10001 regubom && useradd -u 10001 -g 10001 -d /app -s /sbin/nologin regubom

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application source
COPY . .

# Create persistent directories and set non-root permissions
RUN mkdir -p uploads reports data && \
    chown -R regubom:regubom /app && \
    chmod -R 777 uploads reports data

USER regubom

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "300"]
