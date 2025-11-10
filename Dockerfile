# ============================================================
# PBL6 Log Enricher - Production Dockerfile
# Multi-stage build for optimized image size
# Author: tanbrando
# Version: 1.0.0
# ============================================================

FROM python:3.11-slim as builder

LABEL maintainer="tanbrando"
LABEL version="1.0.0"
LABEL description="Log enrichment API with AI analysis for SOC"

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM python:3.11-slim

LABEL maintainer="tanbrando"

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_ENV=production \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app /app/logs /app/parsers/data && \
    chown -R appuser:appuser /app

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=appuser:appuser shared/ /app/shared/
COPY --chown=appuser:appuser parsers/ /app/parsers/
COPY --chown=appuser:appuser scripts/ /app/scripts/

# Create required directories
RUN mkdir -p /app/logs /app/parsers/data/geoip /app/parsers/data/attack_intel && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run application
CMD ["python", "-u", "parsers/unified/app.py"]