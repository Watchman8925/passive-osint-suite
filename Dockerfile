# Multi-stage Docker build for OSINT Suite
# 
# Security Features:
# - Pinned base image digest for reproducibility and security
# - Multi-stage build to minimize attack surface
# - Non-root user (osint) for runtime
# - Minimal runtime dependencies
# - No secrets or credentials in image
# - Automated vulnerability scanning (Trivy, Hadolint, Dockle)
# 
# For detailed security information, see DOCKER_SECURITY.md

# Builder stage - Compile dependencies
FROM python:3.12-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash osint

# Set up Python environment
WORKDIR /app
COPY requirements.txt .

# Install Python packages with better caching and error handling
RUN python -m pip install --no-cache-dir --user --upgrade "pip==25.2" setuptools wheel && \
    pip install --no-cache-dir --user -r requirements.txt

# Create cache directory for models (they will be downloaded at runtime)
RUN mkdir -p /home/osint/.cache/huggingface && \
    chown -R osint:osint /home/osint/.cache

# Production stage
# Use same pinned base image for consistency
FROM python:3.12-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS production

# Upgrade base packages and install minimal runtime deps (remove tor; rely on tor-proxy container)
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
    curl \
    procps \
    ca-certificates \
    libexpat1 \
    && rm -rf /var/lib/apt/lists/*

# Ensure latest secure pip in production environment
RUN python -m pip install --no-cache-dir --upgrade "pip==25.2" setuptools wheel

# Create non-root user
RUN useradd --create-home --shell /bin/bash osint

# Copy Python packages from builder with correct ownership to avoid large chown operations
COPY --from=builder --chown=osint:osint /root/.local /home/osint/.local

# Set up application
WORKDIR /app
COPY --chown=osint:osint . .

# Create required directories with proper permissions without recursive chown
RUN install -d -o osint -g osint /app/output/encrypted /app/output/audit /app/output/logs /app/logs /app/policies

# Switch to non-root user
USER osint

# Set environment variables
ENV PATH=/home/osint/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV OSINT_USE_KEYRING=false
ENV OSINT_TEST_MODE=false
ENV HF_HOME=/home/osint/.cache/huggingface

# OCI labels
LABEL org.opencontainers.image.source="https://github.com/Watchman8925/passive-osint-suite" \
    org.opencontainers.image.description="Passive OSINT Suite API server (hardened)" \
    org.opencontainers.image.licenses="MIT"

# Ensure Hugging Face cache directory exists for the non-root user
RUN mkdir -p "$HF_HOME"

# Enhanced health check for analysis modules
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD python -c "from modules import MODULE_REGISTRY; print(f'Health: {len(MODULE_REGISTRY)} modules loaded')" || exit 1

# Expose API port
EXPOSE 8000

# Default command runs FastAPI via uvicorn for production
CMD ["python", "-m", "uvicorn", "api.api_server:app", "--host", "0.0.0.0", "--port", "8000"]