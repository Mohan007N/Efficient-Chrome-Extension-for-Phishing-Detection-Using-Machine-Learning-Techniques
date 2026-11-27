# Deployment Guide

## 1. Local Python Development
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python src/build_datasets.py
python src/train.py
python src/train_dom.py
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

## 2. Docker & Docker Compose
```bash
docker compose up --build api
```
To start the optional MLflow tracking UI (`http://127.0.0.1:5000`):
```bash
docker compose --profile mlops up --build
```

## 3. Render Deployment
`render.yaml` configures a Python web service using:
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`
- Environment variables: `GROQ_API_KEY` (optional, set manually in dashboard), `ALLOWED_ORIGINS`, `RATE_LIMIT_PER_MIN`.

## 4. Connecting Chrome Extension to Production
1. Deploy the FastAPI backend over **HTTPS** (e.g., Render or Docker behind TLS reverse proxy).
2. Open the extension popup -> click `⚙` -> enter your HTTPS backend URL (e.g. `https://your-service.onrender.com`) -> click **Save**.
3. Confirm the header status pill switches to **Online**.

