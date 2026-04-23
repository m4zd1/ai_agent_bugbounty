# docker/Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    wget \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright browsers
RUN pip install playwright && \
    playwright install chromium && \
    playwright install-deps

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY agent/ ./agent/
COPY config.yaml .
COPY .env.example .env

# Create directories
RUN mkdir -p reports logs memory_store vector_db

# Run as non-root user
RUN useradd -m -s /bin/bash agentuser && \
    chown -R agentuser:agentuser /app
USER agentuser

# Entry point
ENTRYPOINT ["python", "-m", "agent.core"]

# Default command
CMD ["--help"]