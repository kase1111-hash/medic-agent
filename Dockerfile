# Medic Agent - Production Dockerfile
# Phase 7: Deployment & Operations
#
# Multi-stage build for optimized production image

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Production Image
# =============================================================================
FROM python:3.11-slim as production

# Labels
LABEL org.opencontainers.image.title="Medic Agent"
LABEL org.opencontainers.image.description="Autonomous resilience layer for Smith kill report evaluation"
LABEL org.opencontainers.image.version="7.0.0"
LABEL org.opencontainers.image.vendor="Medic Agent Team"

# Create non-root user for security
RUN groupadd -r medic && useradd -r -g medic medic

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=medic:medic . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs && \
    chown -R medic:medic /app/data /app/logs

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MEDIC_CONFIG_PATH=/app/config/medic.yaml \
    MEDIC_LOG_LEVEL=INFO \
    MEDIC_MODE=observer

# Expose ports
# 8000 - Web API
# 9090 - Prometheus metrics
EXPOSE 8000 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=5)" || exit 1

# Switch to non-root user
USER medic

# Default command
ENTRYPOINT ["python", "main.py"]
CMD ["--config", "/app/config/medic.yaml"]

# =============================================================================
# Stage 3: Development Image (optional)
# =============================================================================
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    black \
    mypy \
    ruff

# Mount points for development
VOLUME ["/app/config", "/app/data", "/app/logs"]

USER medic

# Override for development
CMD ["--config", "/app/config/medic.yaml", "--mode", "observer"]
