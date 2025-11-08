# ============================================================
# Unified Log Parser API - Production Dockerfile
# Author: tanbrando
# Date: 2025-01-08 03:08:52 UTC
# ============================================================

FROM python:3.11-slim as builder

LABEL maintainer="tanbrando"
LABEL version="1.0.0"

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================================
# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="tanbrando"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_ENV=production

# Create app user
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app /app/logs /app/data && \
    chown -R appuser:appuser /app

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY --chown=appuser:appuser shared/ /app/shared/
COPY --chown=appuser:appuser parsers/ /app/parsers/
COPY --chown=appuser:appuser scripts/ /app/scripts/

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "-u", "parsers/unified/app.py"]