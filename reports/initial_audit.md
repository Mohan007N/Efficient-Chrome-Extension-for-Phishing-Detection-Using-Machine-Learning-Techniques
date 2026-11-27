# Initial Repository Audit

**Audit Date:** 2026-11-27  
**Repository:** `Mohan007N/Efficient-Chrome-Extension-for-Phishing-Detection-Using-Machine-Learning-Techniques`  
**HEAD Commit at Audit:** `fa36f4c` (with uncommitted local edits present in working tree across `backend/`, `src/`, `dataset/`, `models/`, `reports/`)

---

## 1. Executive Summary

The repository currently implements a **binary phishing / scam URL classifier** backed by a FastAPI service (`backend/`) and a Chrome Manifest V3 extension (`chrome_extension/`). While the project already has a working extension-to-backend pipeline, an XGBoost/HistGradientBoosting classifier trained on PhiUSIIL, a Groq-based explainer (`backend/explainer.py`), and an initial threat-feed index (`backend/intel.py`), a thorough audit reveals structural gaps across **dataset separation, domain-grouped evaluation, DOM behaviour modeling, SSRF/CORS security, multi-dimension risk fusion, extension production readiness, MLOps versioning, automated testing, and documentation**.

---

## 2. Component-by-Component Inspection

### 2.1 Chrome Extension (`chrome_extension/`)
- **`manifest.json`**: Manifest V3 (`version: 1.0.0`). Requests `activeTab`, `scripting`, `storage`, `tabs`, `notifications`, and `<all_urls>`.
- **`content.js` (630 lines)**:
  - Skips non-web protocols (`chrome:`, `chrome-extension:`, `about:`, `data:`, `file:`, etc.) and major SERPs.
  - Deduplicates per-tab session URL via `window.__phishguard_scanned__`, waits `800ms` (or `1500ms` retry if body/HTML appears blank).
  - Extracts 46 numeric/categorical features aligned to PhiUSIIL (`URLLength`, `LineOfCode`, `HasPasswordField`, `HasExternalFormSubmit`, `Pay`, `Bank`, `Crypto`, etc.), hardcoding `Robots = 0` and `NoOfSelfRedirect = 0`.
  - Does **not** collect raw password values, cookies, or auth tokens.
  - Injects an in-page safe toast (`4s` auto-dismiss) or warning banner with an expandable XAI drawer.
  - **Weaknesses**: No separate DOM behaviour vector (external scripts, obfuscated inline JS indicators, fake download buttons, misleading CTA patterns, payment inputs vs credential inputs, cross-origin iframe disclosure, mixed content); no user-confirmed trust override; no debounce on SPA navigation (`history.pushState`).
- **`background.js` (312 lines)**:
  - **Hardcoded local URL**: Line 12 hardcodes `const API_BASE_URL = "http://127.0.0.1:8000";` — cannot reach a deployed production HTTPS backend without code edits.
  - Handles `ANALYZE_PAGE`, `EXPLAIN_URL`, `RESCAN_TAB`.
  - **Security / Architecture flaw**: `callGroqDirectly` (lines 216–274) invokes `https://api.groq.com` directly from the browser extension when a user enters a key in settings, bypassing backend policy and exposing key handling in extension storage.
  - **Missing capabilities**: No request throttling, no domain/URL cache TTL, no scan history log, no false-positive / missed-site feedback forwarding, and no connectivity probe (`/health`).
- **`popup.html` (391 lines), `popup.css` (1450 lines), `popup.js` (919 lines)**:
  - Dark-only theme (`:root` obsidian palette), fixed `380px` width.
  - **Stale UI labels**: `popup.html` displays `48 Feature Inspection` (`telemetryCountBadge` = `48`) and `XGBoost Heuristics` (`footerModel`), while the active saved model is `HistGradientBoostingClassifier` with `56` features. `popup.js` header comments still mention `OpenRouter / Gemini`.
  - **Binary presentation**: Displays only Safe vs. Phishing with a single probability bar; lacks separated Connection Security, Phishing Risk, Malware Risk, Credential Risk, Payment Risk, and Deceptive Behaviour Risk, plus scan history, theme toggle, backend status, false-positive feedback, and user-confirmed trusted-domain controls.

### 2.2 FastAPI Backend (`backend/`)
- **`backend/main.py` (296 lines)**:
  - Endpoints: `GET /`, `GET /health`, `POST /predict`, `POST /explain`, plus recent additions `POST /analyze-url`, `GET /scan`, `GET /unauthorized-sites`, `POST /discover`.
  - **CORS misconfiguration**: `allow_origins=["*"]` with `allow_credentials=True` (unsafe and invalid under CORS spec).
  - **SSRF vulnerability**: `POST /analyze-url` and `GET /scan` pass arbitrary user-supplied URLs directly to `src/web_forensics.py:fetch_url_html` without blocking private/loopback/link-local/metadata IP ranges, without pre-connection DNS validation, without revalidating redirect hops, and without redirect-count limits.
  - **Missing endpoints & safeguards**: No `/version`, `/analyze-dom`, `/analyze-website`, `/model-info`, `/feedback`, `/analytics`, rate limiting, or strict payload size bounds.
- **`backend/predictor.py` (286+ lines)**:
  - Uses a single binary `HistGradientBoostingClassifier` plus `UnauthorizedIntelEngine` (`backend/intel.py`).
  - **Uncommitted rule violations (working tree)**:
    - Hard-flags **all** non-local `IsHTTPS == 0` / `http://` URLs as `0.96 HIGH` phishing/fake (`backend/predictor.py`), contradicting the principle that HTTP indicates insecure transport (`connection_security`), not proof of phishing.
    - Hard-flags **all** unreachable/DNS-failed/connection-reset URLs (`backend/intel.py`) with risk `0.74–0.92`, violating the rule against equating missing DNS/RDAP or firewall blocking with malware.
  - **Lack of multi-dimensional risk fusion**: Outputs a single `phishing_probability` blended heuristically with `backend_risk` rather than returning statistically separated sub-risk assessments (`connection_security`, `phishing_risk`, `malware_risk`, `credential_risk`, `payment_risk`, `deceptive_behavior_risk`) and an explicit `UNKNOWN` level when evidence is insufficient.
- **`backend/intel.py` (460+ lines)**:
  - Loads compressed domain feeds (`dataset/unauthorized_domains.json.gz`, ~1.07M unique domains across HaGeZi Fake/TIF, OpenPhish, Phishing.Database, CERT.pl, Scam-Blocklist) and `dataset/tranco_top1m.json.gz` (1M ranks).
  - Performs RDAP domain-age lookup, TLS socket inspection, storefront text forensics, and optional Groq audit.
  - **Gap**: Lacks URLhaus & PhishTank graceful adapters (respecting API key / rate-limit policies), lacks explicit SSRF-safe HTTP client usage, and currently conflates Tranco/DNS absence with elevated malice.
- **`backend/explainer.py` (366+ lines)**:
  - Rule-based attribution + Groq LLM briefing.
  - **Gap**: Does not compute model feature contributions (e.g. SHAP / permutation importance attribution per risk dimension), does not break down explanations across credential/payment/malware/deceptive dimensions, and mixes correlation statements with definitive claims.
- **`backend/schemas.py` (166 lines)**:
  - Defines `URLFeaturesRequest`, `PredictionResponse`, `HealthResponse`, `ExplainRequest` (still carries legacy `gemini_api_key`), `ExplainResponse`, `AnalyzeURLRequest`, `AnalyzeURLResponse`.
  - Lacks dedicated schemas for `DOMFeaturesRequest`, `WebsiteAssessmentRequest/Response`, `FeedbackRequest/Response`, `ModelInfoResponse`, and `VersionResponse`.

### 2.3 ML Pipeline & Dataset (`src/`, `dataset/`, `models/`, `reports/`)
- **`dataset/PhiUSIIL_Phishing_URL_Dataset.csv` (292,106 rows, 55 columns)**:
  - Contains original PhiUSIIL records **mixed with 78,000 synthetic rows** (`synth-valid-`, `synth-shop-`, `synth-phish-`, `synth-scam-`) and `462` oversampled live-scraped rows (`462 = 77 * 6`).
  - Zero missing values; `286,463` unique domains; `291,721` unique URLs.
  - **Critical ML flaws**:
    1. **Random stratified split** (`src/preprocessing.py:split_and_prepare`) instead of **domain-grouped split** (`GroupShuffleSplit` / `StratifiedGroupKFold`): rows sharing a root domain or synthetic template family leak across train/test splits.
    2. **Unverified / synthetic mixing**: `78,000` synthetic rows generated from templates inflate test accuracy (`0.9999` Accuracy / F1 in `reports/model_comparison_results.csv`), making reported metrics **non-representative of real unseen generalization**.
    3. **No separate DOM dataset**: Only PhiUSIIL numeric counts exist; no rich HTML-derived DOM behaviour dataset (e.g. `PhreshPhish`) is separated into `data/processed/dom_dataset.csv`.
    4. **Large file in git**: `dataset/PhiUSIIL_Phishing_URL_Dataset.csv` is `68.4 MB` (`68.11 MB` in git), triggering GitHub `GH001` (>50 MB) warnings.
- **`src/features.py` & `src/preprocessing.py` & `src/train.py` & `src/predict.py`**:
  - `src/features.py` computes 10 engineered features (`DomainHyphenCount`, `DomainDigitCount`, `IsSuspiciousStoreTLD`, `HasScamDomainKeyword`, `BrandImpersonationScore`, `PayWithoutTrustRatio`, `EmptyToSelfLinkRatio`, `ExternalToSelfLinkRatio`, `AssetsPerLineRatio`, `CommerceAuthRiskInteraction`).
  - `src/preprocessing.py` drops leakage columns (`URLSimilarityIndex`, `TLDLegitimateProb`, `URLCharProb`) and skew columns (`Robots`, `NoOfSelfRedirect`), then encodes `TLD` with `LabelEncoder`.
  - **Code duplication**: `src/predict.py` duplicates alignment/encoding logic already implemented in `backend/predictor.py`.
  - **No Logistic Regression baseline**, **no separate DOM classifier** (`src/train_dom.py`), **no cross-validation / PR-AUC / FPR / FNR / domain-grouped / temporal evaluation**, and **no versioned model metadata registry**.
- **`notebooks/Fake_Login_Detection_EDA.ipynb`**:
  - Cell 6 output contains an unresolved `NameError: name 'plt' is not defined`.

### 2.4 Dependencies, MLOps, Testing & Docs
- **Missing Python packages** (observed in `.venv`): `mlflow`, `pytest`, `httpx`, `shap`, `datasets`, `beautifulsoup4`, `lxml` are not installed; `python-dotenv` is installed in `.venv` but omitted from `requirements.txt`.
- **`render.yaml` & `Procfile`**: `render.yaml` still lists `OPENROUTER_API_KEY` instead of `GROQ_API_KEY`; no `Dockerfile`, `docker-compose.yml`, `.env.example`, or `.github/workflows/` CI/CD exist.
- **No automated `tests/` directory**: Zero unit, DOM fixture, SSRF security, or API integration tests exist in the repository.
- **Documentation**: Only root `README.md` exists (outdated; describes original B.Tech PhiUSIIL RF script and future roadmap rather than actual implemented FastAPI/extension/risk system); `docs/` directory does not exist.

---

## 3. Reproducibility Assessment of Reported Metrics

- `reports/model_comparison_results.csv` currently reports:
  - Decision Tree: Accuracy `0.9975`, F1 `0.9980`, ROC AUC `0.9989`
  - Random Forest: Accuracy `0.9995`, F1 `0.9996`, ROC AUC `1.0000`
  - HistGradientBoosting: Accuracy `0.9999`, F1 `0.9999`, ROC AUC `1.0000`
  - XGBoost: Accuracy `0.9999`, F1 `0.9999`, ROC AUC `1.0000`
- **Verdict**: While deterministic on the current mixed CSV via `src/train.py`, those `0.9999` metrics are **artificially inflated** because:
  1. `78,000` synthetic rows and `6x` oversampled live rows (`462` rows from `77` URLs) are split randomly across train and test sets (`20%` random split), causing near-identical copies to appear in both train and test.
  2. There is no domain-grouped split (`GroupShuffleSplit` on root domain) and no independent temporal/external benchmark evaluation (e.g. held-out `PhreshPhish` dates or unseen domains).

---

## 4. Security & Privacy Audit Findings

| Area | Current State | Risk / Action Required |
|---|---|---|
| SSRF Protection | Unchecked `urllib.request.urlopen` on user URLs | Implement `backend/security.py` validating DNS/IPs (block loopback, private, link-local, metadata `169.254.169.254`), schemes, redirect revalidation, max redirects, max bytes, and timeouts |
| CORS Policy | `allow_origins=["*"]` with `allow_credentials=True` | Configure explicit allowed origins (`chrome-extension://*` + configurable origins) without unsafe wildcard + credentials |
| Secrets Management | `.env` ignored by git; `render.yaml` references `OPENROUTER_API_KEY`; no `.env.example` | Add `.env.example` without secrets; update `render.yaml` to `GROQ_API_KEY`; keep API keys out of extension bundles |
| Extension Privacy | Does not send passwords/cookies | Enforce explicit sanitization rejecting/stripping any credential/cookie/token fields and document collected metadata clearly |
| Rate Limiting & Input Bounds | None in `backend/main.py` | Add request size limits, field bounds in Pydantic, and lightweight per-client rate limiting |

