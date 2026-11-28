"""
backend/main.py — FastAPI Backend for Multi-Layer Website Safety & Trust Assessment (v3.0)

Provides:
- GET /health, GET /version, GET /model-info, GET /analytics
- POST /predict (Chrome Extension compatible + separated ML probabilities vs heuristic risk)
- POST /analyze-url, POST /analyze-dom, POST /analyze-website, POST /scan, GET /scan
- POST /explain (Calibrated-aware SHAP + rule + optional Groq XAI synthesis)
- POST /feedback, GET /feedback (quarantined human-review queue with redacted query values)
- GET /unauthorized-sites
"""

from __future__ import annotations

import asyncio
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
import sys
import threading
import uuid
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.explainer import compute_shap_attributions, generate_explanation
from backend.predictor import PhishingPredictor
from backend.schemas import (
    AnalyzeDOMRequest,
    AnalyzeURLRequest,
    AnalyzeWebsiteRequest,
    ExplainRequest,
    ExplainResponse,
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    ModelInfoResponse,
    PredictionResponse,
    URLFeaturesRequest,
    VersionResponse,
    WebsiteAssessmentResponse,
)
from backend.security import (
    PayloadTooLargeError,
    RateLimiter,
    SSRFBlockedError,
    check_api_key_authorized,
    get_allowed_cors_origins,
    redact_url_query_params,
    safe_fetch_html,
    validate_safe_url,
)

API_VERSION = "3.0.0"
SCHEMA_VERSION = "3.0.0"
MAX_REQUEST_BYTES = 2_000_000
FEEDBACK_FILE = os.path.join(PROJECT_ROOT, "data", "feedback", "reports.jsonl")
_PUBLIC_PATHS = {"/", "/health", "/version", "/docs", "/openapi.json", "/redoc"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("PhishingAPI")

predictor: PhishingPredictor | None = None
rate_limiter = RateLimiter()
_stats_lock = threading.Lock()
_feedback_lock = threading.Lock()
_analytics = {
    "total_scans": 0,
    "risk_distribution": Counter(),
    "high_and_critical_count": 0,
}


def _record_scan_stat(risk_level: str):
    """Store strictly anonymized aggregate statistics (never store user browsing history)."""
    with _stats_lock:
        _analytics["total_scans"] += 1
        _analytics["risk_distribution"][risk_level] += 1
        if risk_level in ("HIGH", "CRITICAL"):
            _analytics["high_and_critical_count"] += 1


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML models, verify registry checksums + classes_, and load threat intel on startup."""
    global predictor
    logger.info("Starting WebShield AI v3.0 API — loading validated URL/DOM models and threat intel...")
    models_dir = os.path.join(PROJECT_ROOT, "models")
    dataset_dir = os.path.join(PROJECT_ROOT, "dataset")
    predictor = PhishingPredictor(models_dir=models_dir, dataset_dir=dataset_dir)
    predictor.load()
    logger.info("WebShield AI v3.0 API initialization finished.")
    yield
    logger.info("Shutting down Website Safety API.")


app = FastAPI(
    title="WebShield AI — Multi-Layer Website Safety & Trust Assessment API",
    description=(
        "v3.0 multi-layer assessment combining calibrated URL ML, static/extension DOM Behaviour ML, "
        "Brand Impersonation, Credential & Payment Risk, Threat Intelligence, and SHAP/Groq Explainable AI."
    ),
    version=API_VERSION,
    lifespan=lifespan,
)

allowed_origins = get_allowed_cors_origins()
allow_creds = "*" not in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_creds,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept", "Authorization", "X-API-Key"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return structured validation errors cleanly without leaking internal paths or stack frames."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid or malformed request payload.", "error_count": len(exc.errors())},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.middleware("http")
async def security_guard_middleware(request: Request, call_next):
    """
    Enforce header + streaming request body size ceiling (defeats chunked bypass),
    per-client sliding-window rate limiting, and optional API key authentication.
    """
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_REQUEST_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request payload exceeds 2 MB limit."})

    # Enforce true byte ceiling even when Transfer-Encoding: chunked omits Content-Length
    if request.method in ("POST", "PUT", "PATCH"):
        chunks: list[bytes] = []
        total_bytes = 0
        async for chunk in request.stream():
            if chunk:
                total_bytes += len(chunk)
                if total_bytes > MAX_REQUEST_BYTES:
                    return JSONResponse(status_code=413, content={"detail": "Streaming request body exceeds 2 MB limit."})
                chunks.append(chunk)
        request._body = b"".join(chunks)

    if request.method != "OPTIONS" and request.url.path not in _PUBLIC_PATHS:
        auth_enabled, authorized = check_api_key_authorized(request.headers)
        if auth_enabled and not authorized:
            return JSONResponse(status_code=401, content={"detail": "Valid API key required."})

    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again shortly."})

    return await call_next(request)


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "WebShield AI — Multi-Layer Website Safety & Trust Assessment API",
        "version": API_VERSION,
        "docs": "/docs",
        "health": "/health",
        "endpoints": [
            "GET /health", "GET /version", "GET /model-info", "GET /analytics",
            "POST /predict", "POST /analyze-url", "POST /analyze-dom",
            "POST /analyze-website", "POST /scan", "GET /scan",
            "POST /explain", "POST /feedback", "GET /feedback", "GET /unauthorized-sites",
        ],
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    if predictor is None:
        return HealthResponse(
            status="degraded",
            model_loaded=False,
            url_model_loaded=False,
            dom_model_loaded=False,
            model_type="N/A",
            feature_count=0,
            threat_intel_loaded=False,
            degraded=True,
            registry_integrity_ok=False,
            model_errors=["Predictor not initialized."],
        )

    url_ok = predictor.url_model_ready()
    dom_ok = predictor.dom_model_ready()
    intel_ok = bool(predictor.intel.loaded and not predictor.intel.degraded)
    integrity_ok = bool(predictor._integrity_ok)
    fully_ready = url_ok and dom_ok and intel_ok and integrity_ok
    any_model = url_ok or dom_ok

    return HealthResponse(
        status="ok" if fully_ready else "degraded",
        model_loaded=any_model,
        url_model_loaded=url_ok,
        dom_model_loaded=dom_ok,
        model_type=predictor.model_type(),
        feature_count=predictor.feature_count(),
        threat_intel_loaded=bool(predictor.intel.loaded),
        degraded=not fully_ready,
        registry_integrity_ok=integrity_ok,
        model_errors=list(predictor._model_errors) + list(predictor.intel.load_errors),
    )


@app.get("/version", response_model=VersionResponse, tags=["Metadata"])
async def get_version():
    manifest_models = (predictor.manifest.get("models") if predictor else {}) or {}
    return VersionResponse(
        api_version=API_VERSION,
        url_model_version=str((manifest_models.get("url_risk") or {}).get("version", "v3.0.0")),
        dom_model_version=str((manifest_models.get("dom_behavior") or {}).get("version", "v3.0.0")),
        schema_version=SCHEMA_VERSION,
    )


@app.get("/model-info", response_model=ModelInfoResponse, tags=["Metadata"])
async def get_model_info():
    if predictor is None:
        raise HTTPException(status_code=503, detail="Models not initialized.")
    return ModelInfoResponse(
        active_manifest=predictor.manifest,
        url_feature_count=len(predictor._url_features),
        dom_feature_count=len(predictor._dom_features),
        threat_intel_status=predictor.intel.status_summary(),
        model_availability=predictor.model_availability_summary(),
    )


@app.post("/predict", response_model=PredictionResponse, tags=["Assessment"])
async def predict(request: URLFeaturesRequest):
    """Chrome Extension assessment endpoint (offloaded from asyncio event loop)."""
    if predictor is None or not predictor.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded.")
    try:
        payload = request.model_dump(exclude_unset=True)
        if request.dom_features is not None:
            payload["dom_features"] = request.dom_features.model_dump(exclude_unset=True)
        result = await asyncio.to_thread(predictor.predict, payload, True)
        _record_scan_stat(result["risk_level"])
        return PredictionResponse(**result)
    except Exception as e:
        logger.error(f"/predict error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Prediction failed.")


def _build_assessment_response(raw_assessment: dict) -> WebsiteAssessmentResponse:
    pub = {k: v for k, v in raw_assessment.items() if not k.startswith("_")}
    return WebsiteAssessmentResponse(**pub)


def _normalize_input_url(raw_url: str) -> str:
    clean = (raw_url or "").strip()
    if clean and "://" not in clean and not clean.lower().startswith(("file:", "javascript:", "data:", "vbscript:")):
        clean = f"https://{clean}"
    return clean


@app.post("/analyze-url", response_model=WebsiteAssessmentResponse, tags=["Assessment"])
async def analyze_url(request: AnalyzeURLRequest):
    """Analyze a URL using URL ML, Brand Impersonation, Threat Intel, and optional SSRF-safe live fetch."""
    if predictor is None or not predictor.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded.")

    clean_url = _normalize_input_url(request.url)

    try:
        await asyncio.to_thread(validate_safe_url, clean_url, request.fetch_live)
    except SSRFBlockedError as se:
        raise HTTPException(status_code=400, detail=f"URL rejected by SSRF guard: {se}")

    html = None
    redirect_chain = None
    if request.fetch_live:
        try:
            final_url, status, fetched_html, redirect_chain = await asyncio.to_thread(safe_fetch_html, clean_url)
            clean_url = final_url
            if status < 400:
                html = fetched_html
        except SSRFBlockedError as se:
            raise HTTPException(status_code=400, detail=f"Blocked by SSRF guard: {se}")
        except PayloadTooLargeError as pe:
            raise HTTPException(status_code=413, detail=f"Response exceeded safe size limit: {pe}")
        except Exception as e:
            logger.info(f"Live fetch skipped for {clean_url}: {e}")

    res = await asyncio.to_thread(
        predictor.assess_website,
        url=clean_url,
        html=html,
        redirect_chain=redirect_chain,
        deep_scan=request.deep_scan,
    )
    _record_scan_stat(res["overall_risk_level"])
    return _build_assessment_response(res)


@app.post("/analyze-dom", response_model=WebsiteAssessmentResponse, tags=["Assessment"])
async def analyze_dom(request: AnalyzeDOMRequest):
    """Analyze DOM behaviour either from static HTML or structured DOMFeaturesPayload."""
    if predictor is None or not predictor.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded.")
    if not request.html and not request.dom_features:
        raise HTTPException(status_code=400, detail="Provide either 'html' or 'dom_features'.")

    dom_dict = request.dom_features.model_dump(exclude_unset=True) if request.dom_features is not None else None
    res = await asyncio.to_thread(
        predictor.assess_website,
        url=request.url,
        dom_features=dom_dict,
        html=request.html,
        deep_scan=False,
    )
    _record_scan_stat(res["overall_risk_level"])
    return _build_assessment_response(res)


@app.post("/analyze-website", response_model=WebsiteAssessmentResponse, tags=["Assessment"])
async def analyze_website(request: AnalyzeWebsiteRequest):
    """Comprehensive multi-layer website safety assessment across URL, DOM, Brand, Payment & Threat Intel."""
    if predictor is None or not predictor.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded.")

    clean_url = _normalize_input_url(request.url)

    try:
        await asyncio.to_thread(validate_safe_url, clean_url, request.fetch_live)
    except SSRFBlockedError as se:
        raise HTTPException(status_code=400, detail=f"URL rejected by SSRF guard: {se}")

    html = request.html
    redirect_chain = list(request.redirect_chain or [])
    if request.fetch_live and not html:
        try:
            final_url, status, fetched_html, fetched_chain = await asyncio.to_thread(safe_fetch_html, clean_url)
            clean_url = final_url
            redirect_chain = fetched_chain
            if status < 400:
                html = fetched_html
        except SSRFBlockedError as se:
            raise HTTPException(status_code=400, detail=f"Blocked by SSRF guard: {se}")
        except PayloadTooLargeError as pe:
            raise HTTPException(status_code=413, detail=f"Response exceeded safe size limit: {pe}")
        except Exception as e:
            logger.info(f"Live fetch skipped for {clean_url}: {e}")

    dom_dict = request.dom_features.model_dump(exclude_unset=True) if request.dom_features is not None else None
    res = await asyncio.to_thread(
        predictor.assess_website,
        url=clean_url,
        dom_features=dom_dict,
        html=html,
        redirect_chain=redirect_chain,
        deep_scan=request.deep_scan,
    )
    _record_scan_stat(res["overall_risk_level"])
    return _build_assessment_response(res)


@app.post("/scan", response_model=WebsiteAssessmentResponse, tags=["Assessment"])
async def scan_post(request: AnalyzeURLRequest):
    """SSRF-safe live URL scan (POST)."""
    req = AnalyzeURLRequest(
        url=request.url,
        fetch_live=True,
        deep_scan=request.deep_scan,
    )
    return await analyze_url(req)


@app.get("/scan", response_model=WebsiteAssessmentResponse, tags=["Assessment"])
async def scan_get(url: str, deep_scan: bool = True):
    """SSRF-safe live URL scan (GET convenience endpoint)."""
    return await analyze_url(AnalyzeURLRequest(url=url, fetch_live=True, deep_scan=deep_scan))


def _compute_explain_sync(request: ExplainRequest) -> dict:
    attributions = []
    if predictor is not None and predictor.is_ready() and request.url:
        if predictor.url_model_ready() and "url_length" in predictor._url_features:
            df_u = predictor.prepare_url_dataframe(request.url)
            attributions.extend(compute_shap_attributions(predictor._url_model, df_u, top_k=3))
        if predictor.dom_model_ready() and request.features:
            df_d = predictor.prepare_dom_dataframe(request.features, url=request.url)
            attributions.extend(compute_shap_attributions(predictor._dom_model, df_d, top_k=3))

    return generate_explanation(
        url=request.url,
        hostname=request.hostname or (urlparse(request.url).hostname or ""),
        is_phishing=bool(request.is_phishing),
        risk_level=request.risk_level or "HIGH",
        phishing_prob=request.phishing_probability,
        features_dict=request.features or {},
        api_key=request.groq_api_key,
        assessment=request.assessment,
        attributions=attributions,
        heuristic_risk_index=request.heuristic_risk_index,
    )


@app.post("/explain", response_model=ExplainResponse, tags=["Explainable AI"])
async def explain(request: ExplainRequest):
    """Generate calibrated SHAP/feature-attribution + rule + optional Groq XAI breakdown."""
    try:
        exp = await asyncio.to_thread(_compute_explain_sync, request)
        return ExplainResponse(**exp)
    except Exception as e:
        logger.error(f"/explain error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Explanation generation failed.")


def _write_feedback_record_sync(record: dict):
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    with _feedback_lock:
        with open(FEEDBACK_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def _read_feedback_summary_sync() -> dict:
    counts: Counter = Counter()
    total = 0
    if os.path.exists(FEEDBACK_FILE):
        with _feedback_lock:
            with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        item = json.loads(line)
                        counts[item.get("report_type", "unknown")] += 1
                        total += 1
    return {"total_reports": total, "by_type": dict(counts)}


@app.post("/feedback", response_model=FeedbackResponse, tags=["Feedback & Monitoring"])
async def submit_feedback(request: FeedbackRequest):
    """
    Store user-submitted false positive or missed threat reports in a human-review queue.
    Strips sensitive query parameter values before persisting.
    """
    sanitized_url = redact_url_query_params(request.url.strip())[:2048]
    parsed = urlparse(sanitized_url)
    record = {
        "report_id": str(uuid.uuid4()),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "domain": (parsed.hostname or "").lower(),
        "url": sanitized_url,
        "report_type": request.report_type,
        "reported_risk_level": request.reported_risk_level,
        "expected_category": request.expected_category,
        "notes": (request.notes or "").strip()[:1000],
        "verification_status": "pending_human_review",
    }
    await asyncio.to_thread(_write_feedback_record_sync, record)
    return FeedbackResponse(
        status="recorded",
        report_id=record["report_id"],
        verification_status="pending_human_review",
        message="Feedback logged (with query secrets redacted) for human verification.",
    )


@app.get("/feedback", tags=["Feedback & Monitoring"])
async def list_feedback_summary():
    """Return aggregate feedback counts (avoids exposing raw user browsing URLs)."""
    return await asyncio.to_thread(_read_feedback_summary_sync)


@app.get("/analytics", tags=["Feedback & Monitoring"])
async def get_analytics():
    """Return anonymized aggregate scan statistics, model version, and threat feed status."""
    fb = await list_feedback_summary()
    manifest_models = (predictor.manifest.get("models") if predictor else {}) or {}
    with _stats_lock:
        snapshot = {
            "total_scans": _analytics["total_scans"],
            "risk_distribution": dict(_analytics["risk_distribution"]),
            "high_and_critical_count": _analytics["high_and_critical_count"],
        }
    ready_all = bool(
        predictor and predictor.url_model_ready() and predictor.dom_model_ready()
        and predictor.intel.loaded and not predictor.intel.degraded and predictor._integrity_ok
    )
    snapshot.update({
        "feedback_stats": fb,
        "backend_health": "ok" if ready_all else "degraded",
        "url_model_version": (manifest_models.get("url_risk") or {}).get("version", "v3.0.0"),
        "dom_model_version": (manifest_models.get("dom_behavior") or {}).get("version", "v3.0.0"),
        "threat_intel_status": predictor.intel.status_summary() if predictor else {},
        "model_availability": predictor.model_availability_summary() if predictor else {},
    })
    return snapshot


@app.get("/unauthorized-sites", tags=["Threat Intelligence"])
async def list_unauthorized_sites(q: str = "", category: str = "", limit: int = 50):
    if predictor is None:
        raise HTTPException(status_code=503, detail="Backend is initializing.")
    sites = await asyncio.to_thread(predictor.intel.search_catalog, q, category, limit)
    return {"count": len(sites), "sites": sites}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    reload_flag = os.environ.get("RENDER") is None and os.environ.get("DOCKER_ENV") is None
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=reload_flag)
