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

from backend.schemas import (
    AnalyzeURLRequest,
    AnalyzeURLResponse,
    ExplainRequest,
    ExplainResponse,
    HealthResponse,
    PredictionResponse,
    URLFeaturesRequest,
)
from backend.predictor import PhishingPredictor
from backend.explainer import generate_explanation
from src.web_forensics import extract_phiusiil_features_from_html, fetch_url_html

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
    dataset_dir = os.path.join(PROJECT_ROOT, "dataset")
    predictor = PhishingPredictor(models_dir=models_dir, dataset_dir=dataset_dir)
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
        "analyze_url": "POST /analyze-url",
        "scan": "GET /scan?url=...",
        "unauthorized_sites": "GET /unauthorized-sites",
        "discover": "POST /discover",
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
    Utilizes Groq AI API, with intelligent rule-based technical feature attribution as fallback.
    """
    try:
        merged_features = dict(request.features or {})
        if predictor is not None and predictor.is_ready() and (request.url or request.hostname):
            try:
                fast_intel = predictor.intel.inspect_domain(
                    request.url,
                    request.hostname or "",
                    merged_features,
                    deep_scan=not predictor.intel.is_trusted(request.hostname or ""),
                    use_ai_audit=False,
                )
                if fast_intel.get("indicators"):
                    merged_features["_backend_indicators"] = fast_intel["indicators"]
            except Exception:
                pass

        explanation_data = generate_explanation(
            url=request.url,
            hostname=request.hostname,
            is_phishing=request.is_phishing,
            risk_level=request.risk_level,
            phishing_prob=request.phishing_probability,
            features_dict=merged_features,
            api_key=request.groq_api_key or request.gemini_api_key,
        )
        return ExplainResponse(**explanation_data)
    except Exception as e:
        logger.error(f"Explanation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")


def _run_direct_url_scan(target_url: str, use_ai_audit: bool = True) -> AnalyzeURLResponse:
    """Shared backend URL analyzer used by both POST /analyze-url and GET /scan."""
    if predictor is None or not predictor.is_ready():
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    clean_url = target_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = f"https://{clean_url}"

    from urllib.parse import urlparse
    parsed = urlparse(clean_url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="Invalid URL provided.")

    features_dict: dict = {"url": clean_url, "URL": clean_url, "hostname": host, "Domain": host}
    try:
        final_url, status, html = fetch_url_html(clean_url, timeout=6.0, max_bytes=350_000)
        if status < 400 and html and len(html) >= 200:
            extracted = extract_phiusiil_features_from_html(final_url or clean_url, html, label=1)
            if extracted:
                features_dict.update(extracted)
                features_dict["url"] = final_url or clean_url
                features_dict["hostname"] = (urlparse(features_dict["url"]).hostname or host).lower()
    except Exception as e:
        logger.info(f"Live HTML fetch skipped for {clean_url}: {e}")

    pred = predictor.predict(features_dict, deep_scan=True, use_ai_audit=use_ai_audit)
    intel_info = (
        {}
        if pred["whitelisted"]
        else predictor.intel.inspect_domain(
            features_dict["url"],
            features_dict["hostname"],
            features_dict,
            deep_scan=True,
            use_ai_audit=use_ai_audit,
        )
    )

    exp = generate_explanation(
        url=features_dict["url"],
        hostname=features_dict["hostname"],
        is_phishing=pred["is_phishing"],
        risk_level=pred["risk_level"],
        phishing_prob=pred["phishing_probability"],
        features_dict={**features_dict, "_backend_indicators": pred["top_indicators"]},
    )

    forensics = intel_info.get("forensics") or {}
    return AnalyzeURLResponse(
        url=features_dict["url"],
        hostname=features_dict["hostname"],
        is_unauthorized_or_phishing=pred["is_phishing"],
        risk_probability=pred["phishing_probability"],
        legitimate_probability=pred["legitimate_probability"],
        verdict=pred["verdict"],
        risk_level=pred["risk_level"],
        whitelisted=pred["whitelisted"],
        tranco_rank=intel_info.get("tranco_rank"),
        domain_age_days=(intel_info.get("rdap") or {}).get("domain_age_days"),
        registry_match=intel_info.get("registry_match") or {},
        forensic_summary={
            "is_commerce_or_portal": forensics.get("is_commerce_or_portal"),
            "official_emails": forensics.get("official_emails"),
            "free_emails": forensics.get("free_emails"),
            "has_corp_id": forensics.get("has_corp_id"),
            "has_prepaid": forensics.get("has_prepaid"),
            "has_cod": forensics.get("has_cod"),
            "restrictive_refund_clauses": forensics.get("restrictive_refund_clauses"),
            "forensic_risk_score": forensics.get("forensic_risk_score"),
        },
        ai_audit=intel_info.get("ai_audit"),
        top_indicators=pred["top_indicators"],
        explanation=exp.get("explanation", ""),
    )


@app.post("/analyze-url", response_model=AnalyzeURLResponse, tags=["Unauthorized Website Scanner"])
async def analyze_url(request: AnalyzeURLRequest):
    """Fetch, inspect, and evaluate any URL directly on the backend (ML + RDAP + TLS + Forensics + AI)."""
    return _run_direct_url_scan(request.url, use_ai_audit=request.use_ai_audit)


@app.get("/scan", response_model=AnalyzeURLResponse, tags=["Unauthorized Website Scanner"])
async def scan_url(url: str, use_ai_audit: bool = True):
    """GET convenience endpoint to scan any target URL from browser/CLI/Swagger UI."""
    return _run_direct_url_scan(url, use_ai_audit=use_ai_audit)


@app.get("/unauthorized-sites", tags=["Unauthorized Website Discovery"])
async def list_unauthorized_sites(q: str = "", category: str = "", limit: int = 50):
    """Search and list real-world unauthorized, fake-shopping, and scam websites discovered by the backend."""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Backend is initializing.")
    sites = predictor.intel.search_catalog(query=q, category=category, limit=limit)
    return {"count": len(sites), "sites": sites}


@app.post("/discover", tags=["Unauthorized Website Discovery"])
async def refresh_discovery(probe_live: bool = False):
    """Refresh threat/fake-shop feeds and reload the backend's unauthorized website registry."""
    from src.discover_unauthorized_sites import discover_and_build
    summary = discover_and_build(probe_live=probe_live)
    if predictor is not None:
        predictor.intel.load()
    return {"status": "refreshed", "summary": summary}


# ---------------------------------------------------------------------------
# Entry point (works both locally and on Render)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    reload_flag = os.environ.get("RENDER") is None  # disable reload on Render
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=reload_flag)
