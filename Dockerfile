# Zscaler Bulk URL Uploader Docker Image
FROM python:3.11-slim

LABEL maintainer="dunwright@gmail.com"
LABEL description="Zscaler Bulk URL Uploader - Secure bulk upload of URLs to ZIA custom categories"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd -r zscaler && useradd -r -g zscaler -d /app -s /bin/bash zscaler

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY zscaler_bulk_uploader.py .
COPY config.sample.yaml .
COPY examples/ ./examples/
COPY README.md .
COPY LICENSE .

# Create necessary directories
RUN mkdir -p /app/logs /app/config /app/data && \
    chown -R zscaler:zscaler /app

# Switch to non-root user
USER zscaler

# Create volume for configuration and data
VOLUME ["/app/config", "/app/data", "/app/logs"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import zscaler_bulk_uploader; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "zscaler_bulk_uploader.py"]
CMD ["--help"]

# Usage examples in comments:
# Build: docker build -t zscaler-uploader .
# Run:   docker run -v $(pwd)/config:/app/config -v $(pwd)/data:/app/data zscaler-uploader --csv /app/data/urls.csv --config /app/config/config.yaml
