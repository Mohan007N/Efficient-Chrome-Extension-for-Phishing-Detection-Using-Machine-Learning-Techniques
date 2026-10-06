"""
backend/main.py — FastAPI Backend for Phishing URL Detection

Serves the trained XGBoost model via a REST API.
The Chrome Extension POSTs extracted page features here
and receives a phishing probability score in response.

Run with:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
Or from the project root:
    python backend/main.py
"""

import os
import sys
import logging
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure the project root is in sys.path so src.* imports work
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.schemas import URLFeaturesRequest, PredictionResponse, HealthResponse, ExplainRequest, ExplainResponse
from backend.predictor import PhishingPredictor
from backend.explainer import generate_explanation

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("PhishingAPI")

# ---------------------------------------------------------------------------
# Global predictor instance (loaded once at startup)
# ---------------------------------------------------------------------------
predictor: PhishingPredictor = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the ML model on startup, release resources on shutdown."""
    global predictor
    logger.info("🚀 Starting PhishingDetection API — loading model artifacts...")
    models_dir = os.path.join(PROJECT_ROOT, "models")
    predictor = PhishingPredictor(models_dir=models_dir)
    predictor.load()
    logger.info("✅ Model loaded successfully. API is ready.")
    yield
    logger.info("🛑 Shutting down PhishingDetection API.")


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI Phishing & Fake Login Page Detector",
    description=(
        "REST API that accepts URL/page features extracted by the Chrome Extension "
        "and returns a real-time phishing probability score using a trained XGBoost classifier."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow Chrome Extension (chrome-extension://*) and local dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # In production, restrict to your extension origin
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "AI Phishing Detection API is running.",
        "docs": "/docs",
        "health": "/health",
        "predict": "POST /predict",
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Returns API and model health status."""
    model_loaded = predictor is not None and predictor.is_ready()
    return HealthResponse(
        status="ok" if model_loaded else "degraded",
        model_loaded=model_loaded,
        model_type=predictor.model_type() if model_loaded else "N/A",
        feature_count=predictor.feature_count() if model_loaded else 0,
    )


@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
async def predict(request: URLFeaturesRequest):
    """
    Accepts extracted URL/page features and returns a phishing prediction.

    - **is_phishing**: True if the page is classified as phishing.
    - **phishing_probability**: Confidence score (0.0 – 1.0) that the page is phishing.
    - **legitimate_probability**: Confidence score that the page is legitimate.
    - **verdict**: Human-readable verdict string.
    - **risk_level**: 'HIGH', 'MEDIUM', or 'LOW'.
    """
    if predictor is None or not predictor.is_ready():
        raise HTTPException(
            status_code=503,
            detail="Model is not loaded. Please restart the server and ensure model artifacts exist.",
        )

    try:
        result = predictor.predict(request.dict())
        logger.info(
            f"Prediction for URL (len={request.URLLength}): "
            f"{result['verdict']} | confidence={result['phishing_probability']:.3f}"
        )
        return PredictionResponse(**result)
    except Exception as e:
        logger.error(f"Prediction error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.post("/explain", response_model=ExplainResponse, tags=["Explainable AI"])
async def explain(request: ExplainRequest):
    """
    Explainable AI (XAI) Endpoint:
    Provides a detailed incident breakdown of why a website was flagged or deemed safe.
    Utilizes Google Gemini API if an API key is provided, with intelligent
    rule-based technical feature attribution as fallback.
    """
    try:
        explanation_data = generate_explanation(
            url=request.url,
            hostname=request.hostname,
            is_phishing=request.is_phishing,
            risk_level=request.risk_level,
            phishing_prob=request.phishing_probability,
            features_dict=request.features or {},
            api_key=request.gemini_api_key,
        )
        return ExplainResponse(**explanation_data)
    except Exception as e:
        logger.error(f"Explanation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")


# ---------------------------------------------------------------------------
# Entry point (works both locally and on Render)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    reload_flag = os.environ.get("RENDER") is None  # disable reload on Render
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=reload_flag)
