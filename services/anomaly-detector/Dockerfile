FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Create models directory and copy models
RUN mkdir -p /app/models
COPY models/ /app/models/

# Create non-root user
RUN useradd -m -u 1001 appuser && chown -R appuser:appuser /app/models
USER appuser

EXPOSE 5000

CMD ["python", "src/main.py"]
