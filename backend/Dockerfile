FROM python:3.13-slim

# Install system dependencies required by WeasyPrint (Pango/Cairo), psycopg2
# compilation, and general tooling. curl is included so Semgrep can fetch
# remote rule sets at scan time without outbound-network restrictions.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    libffi-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy requirements file first to leverage Docker layer caching —
# this layer is only rebuilt when requirements.txt changes.
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code into /app/backend so that the module path
# backend.main:app resolves correctly with PYTHONPATH=/app
COPY . /app/backend

# Create uploads directory (will be overridden by the bind-mount volume in
# docker-compose, but ensures the path exists for standalone container runs)
RUN mkdir -p /app/uploads

# Expose application port
EXPOSE 8000

# PYTHONPATH allows "import backend.*" to resolve from /app
ENV PYTHONPATH=/app

# Production entrypoint — no --reload (dev-only flag)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
