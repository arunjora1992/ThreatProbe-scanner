FROM python:3.12-slim

# nmap is required by the worker for network/server scanning.
# ca-certificates + tzdata keep TLS checks and timestamps correct.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates tzdata curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Default command runs the API; the worker overrides this in docker-compose.
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
