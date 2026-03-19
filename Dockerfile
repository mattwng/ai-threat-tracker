FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x scripts/threat_fetch.py

EXPOSE 5003

ENV TZ=America/Los_Angeles
ENV PYTHONUNBUFFERED=1

# 1 worker, 4 threads — prevents multiple APScheduler instances
CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "1", "--threads", "4", "--timeout", "120", "threat_tracker_app:app"]
