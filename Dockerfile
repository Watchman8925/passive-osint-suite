# Multi-stage Docker build for OSINT Suite
FROM python:3.12-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    tor \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash osint

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.12-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    tor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash osint

# Copy Python packages from builder
COPY --from=builder /root/.local /home/osint/.local

# Set up application
WORKDIR /app
COPY --chown=osint:osint . .

# Create required directories
RUN mkdir -p output/encrypted output/audit output/logs logs policies \
    && chown -R osint:osint /app

# Configure Tor
COPY --chown=osint:osint docker/torrc /etc/tor/torrc

# Switch to non-root user
USER osint

# Set environment variables
ENV PATH=/home/osint/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV OSINT_USE_KEYRING=false
ENV OSINT_TEST_MODE=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose API port
EXPOSE 8000

# Default command runs FastAPI via uvicorn for production
CMD ["python", "-m", "uvicorn", "api.api_server:app", "--host", "0.0.0.0", "--port", "8000"]