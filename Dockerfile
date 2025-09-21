# Production Dockerfile for simple-port-checker
FROM python:3.12-slim-bookworm

# Set metadata
LABEL maintainer="htunn <htunnthuthu.linux@gmail.com>"
LABEL description="A comprehensive tool for checking firewall ports, L7 protection services, and SSL/TLS certificate analysis"
LABEL version="0.5.1"
LABEL org.opencontainers.image.source="https://github.com/htunn/simple-port-checker"
LABEL org.opencontainers.image.documentation="https://github.com/htunn/simple-port-checker#readme"
LABEL org.opencontainers.image.licenses="MIT"

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user and install system dependencies
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install the application and change ownership
RUN pip install --upgrade pip && \
    pip install . && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Create directory for user data
RUN mkdir -p /home/appuser/.local/share/simple-port-checker

# Set default working directory for user
WORKDIR /home/appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD port-checker --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["port-checker"]
CMD ["--help"]
