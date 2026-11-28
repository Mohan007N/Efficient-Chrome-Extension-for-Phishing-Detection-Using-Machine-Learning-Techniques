FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOCKER_ENV=1 \
    PORT=8000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy core backend, ML pipeline, versioned model artifacts, and lightweight runtime intel snapshots
# Raw training datasets (e.g. PhiUSIIL 71MB) are intentionally excluded.
COPY backend/ ./backend/
COPY src/ ./src/
COPY models/ ./models/
COPY data/external/ ./data/external/
COPY data/intel/ ./data/intel/
COPY dataset/unauthorized_domains.json.gz dataset/tranco_top1m.json.gz dataset/discovered_unauthorized_sites.csv ./dataset/

RUN mkdir -p /app/data/feedback /app/logs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import json,urllib.request; d=json.loads(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).read()); assert d['url_model_loaded'] and d['dom_model_loaded'] and d['threat_intel_loaded'], d" || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
