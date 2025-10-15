FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# Install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Add app code
COPY . .

# Run the Flask API with gunicorn (use $PORT provided by Cloud Run / env)
CMD ["sh", "-c", "gunicorn -w 2 -k gthread -b :${PORT:-8080} api:app"]
