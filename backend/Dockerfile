# Backend Dockerfile for production
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy source
COPY . .

# Expose port
EXPOSE 5000

# Environment (override in deployment)
ENV FLASK_ENV=production \
    PYTHONPATH=/app

# Start with eventlet worker for Socket.IO
CMD ["python", "run.py"]
