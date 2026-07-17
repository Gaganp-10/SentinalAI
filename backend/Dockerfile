FROM python:3.11-slim

# Install system dependencies for WeasyPrint and compilation
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
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy requirements file first to utilize Docker layer caching
COPY requirements.txt .

# Install Python requirements
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/backend

# Create upload directory
RUN mkdir -p /app/uploads

# Expose port
EXPOSE 8000

# Set Python path to find backend package
ENV PYTHONPATH=/app

# Start the application using Uvicorn
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
