# API Documentation

Base URL (local): `http://127.0.0.1:8000`  
Interactive Swagger UI: `/docs` | OpenAPI JSON: `/openapi.json`

## Endpoints

### `GET /health`
Returns backend readiness, URL/DOM model availability, active feature counts, and threat intelligence load status.

### `GET /version`
Returns `api_version`, `url_model_version`, `dom_model_version`, and `schema_version`.

### `GET /model-info`
Returns the active versioned model registry manifest (`models/registry/active_manifest.json`), feature counts, and threat intelligence feed counts.

### `POST /predict`
Backward-compatible Chrome Extension assessment endpoint accepting `URLFeaturesRequest` (legacy 46 fields + optional `dom_features` + `redirect_chain`). Returns `PredictionResponse` including the full multi-dimensional `assessment` object.

### `POST /analyze-url`
Evaluates a URL (`{"url": "https://...", "fetch_live": false, "deep_scan": true}`) using Model 1 (URL ML), Model 3 (Brand Impersonation), and Model 5 (Threat Intelligence). Rejects private/loopback/metadata URLs via SSRF guard (`HTTP 400`).

### `POST /analyze-dom`
Analyzes DOM behaviour from either raw static `html` (parsed with BeautifulSoup without executing JavaScript) or structured `dom_features` (`DOMFeaturesPayload`).

### `POST /analyze-website`
Full multi-layer website safety evaluation combining URL, DOM/HTML, redirects, Brand Impersonation, Credential/Payment Risk, and Threat Intelligence.

### `POST /scan` & `GET /scan?url=...`
Convenience live-fetch endpoints protected by `backend/security.py` SSRF checks (DNS resolution validation, private/link-local IP blocking, max 3 revalidated redirects, 1.5 MB ceiling).

### `POST /explain`
Generates human-readable risk explanations using SHAP/feature-importance attributions (`shap.TreeExplainer`), dimension evidence, and optional Groq LLM synthesis.

### `POST /feedback` & `GET /feedback`
Logs user false-positive or missed-threat reports to `data/feedback/reports.jsonl` with `verification_status: "pending_human_review"`. Reports are never promoted automatically to training labels. `GET /feedback` returns aggregate counts only.

### `GET /analytics`
Returns anonymized aggregate scan counts, risk-level distribution, feedback stats, model versions, and threat-feed status without exposing private browsing URLs.

