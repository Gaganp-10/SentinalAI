FROM python:3.13-slim

# Install system dependencies required by psycopg2 compilation and general tooling.
# curl is included so Semgrep can fetch remote rule sets if needed.
# Note: Pango/Cairo libraries are removed since WeasyPrint was replaced by xhtml2pdf.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libffi-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root group and user for security
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -d /app -s /sbin/nologin appuser

# Set working directory inside the container
WORKDIR /app

# Copy requirements file first to leverage Docker layer caching —
# this layer is only rebuilt when requirements.txt changes.
COPY requirements.txt .

# Upgrade pip and install Python dependencies with timeout/retries for resilience
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --default-timeout=100 -r requirements.txt

# Copy application source code into /app/backend so that the module path
# backend.main:app resolves correctly with PYTHONPATH=/app
COPY . /app/backend

# Create uploads directory and set non-root ownership
RUN mkdir -p /app/uploads && chown -R appuser:appuser /app

# Expose application port
EXPOSE 8000

# PYTHONPATH allows "import backend.*" to resolve from /app
ENV PYTHONPATH=/app

# Run container process as non-root user
USER appuser

# Production entrypoint — no --reload (dev-only flag)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
