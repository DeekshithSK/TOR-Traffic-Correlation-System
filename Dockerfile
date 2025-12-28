# Backend Dockerfile
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (libpcap for Scapy)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage cache
COPY requirements.txt .

# Install Python dependencies
# We use --no-cache-dir to keep image small
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create evidence store directory
RUN mkdir -p .evidence_store

# Expose API port
EXPOSE 8000

# Run the API
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
