# ---- Base image ----
FROM python:3.11-slim

# Helpful defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (grpc etc. sometimes need build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# App code
COPY . .

# Render provides $PORT at runtime
ENV PORT=8080
EXPOSE 8080

# Start Gunicorn (Flask app in api.py as 'app')
CMD ["bash", "-lc", "gunicorn api:app --bind 0.0.0.0:${PORT}"]
