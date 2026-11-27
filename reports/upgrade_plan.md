# System Upgrade Plan (Phases 1–10)

## Goal
Transform the existing binary phishing detector into a **multi-layer, explainable, privacy-conscious Website Safety, Phishing Detection & Trust Assessment System** covering URL risk, DOM behaviour, brand impersonation, credential/payment risks, malware/download risks, deceptive UX, transport security, and threat intelligence.

---

## Phase-by-Phase Execution Plan

### Phase 1: Repository Audit (Current Phase — Complete before modifying project)
- Produce `reports/initial_audit.md`, `reports/feature_inventory.md`, and `reports/upgrade_plan.md`.
- Preserve existing directory layout and backward compatibility where practical.

### Phase 2: Multi-Source Dataset Engineering (`src/dataset_validation.py`, `src/build_datasets.py`)
1. **Verified Sources (No synthetic label contamination in ground truth):**
   - **PhiUSIIL** (existing `dataset/PhiUSIIL_Phishing_URL_Dataset.csv` filtered to strip prior synthetic rows `synth-*` / `valid-site-*` / `verify-login-*` / `valid-shop-*` / `scam-shop-*` so real ground-truth rows remain pure).
   - **PhreshPhish** (`huggingface.co/datasets/phreshphish/phreshphish`, `CC-BY-4.0`) fetched safely via Hugging Face Datasets Server API (`train` & `test` dates, URLs, labels, `target` brands, and real HTML!) — **never** executing webpage JS.
   - **OpenPhish** (`openphish.com/feed.txt`) + **Tranco Top-1M** (benign domain candidates; never blindly trusted without checks) + graceful optional **PhishTank** / **URLhaus** adapters (respecting API keys & rate limits) + curated **custom verified records** (`data/external/custom_verified.csv`, explicitly tagging multi-label risk categories such as `payment_risk`, `brand_impersonation`, `deceptive_behavior`, `malware_distribution`, `credential_risk`, `suspicious_redirect`).
2. **Standardized Multi-Label & Provenance Schema:**
   - Columns: `url`, `domain`, `source`, `collection_timestamp`, `verification_status`, `html_available`, `primary_label`, `risk_labels` (pipe/JSON multi-label: `benign`, `phishing`, `brand_impersonation`, `malware_distribution`, `credential_risk`, `payment_risk`, `deceptive_behavior`, `suspicious_redirect`, `unknown`), `confidence`, `evidence`, `date`.
   - Separate uncertain/unverified samples (`data/processed/uncertain_samples.csv`) from verified training samples.
3. **Preprocessing & Domain-Grouped Evaluation:**
   - URL & HTML normalization, exact/URL deduplication, domain-grouped splitting (`StratifiedGroupKFold` / `GroupShuffleSplit` by `root_domain`), plus temporal split evaluation on `PhreshPhish` dates.
   - Outputs: `data/processed/url_dataset.csv`, `data/processed/dom_dataset.csv`, `data/processed/combined_dataset.csv`.
   - Git hygiene: add large raw/processed CSVs and `.gz` feeds to `.gitignore` so large datasets/sensitive downloads are never committed to GitHub.

### Phase 3: Separated Feature Engineering (`src/features.py`, `src/dom_features.py`)
- **`src/features.py`**: Refactor into clean, URL-only + domain-only feature extraction (`27` features: entropy, Punycode, port, shortener, dot/hyphen/special counts, TLD encoding, brand similarity, typosquatting edit distance) plus shared brand/domain helpers. Never treat missing RDAP/DNS as malicious.
- **`src/dom_features.py`**: Extract all 5 groups of DOM/HTML behaviour features identically from offline HTML (`BeautifulSoup` / `html.parser`) and from live browser DOM snapshots sent by the extension, recording `cross_origin_iframes_uninspected` and `unavailable_signals`.

### Phase 4: Multi-Model ML Architecture (`src/train.py`, `src/train_dom.py`, `src/model_registry.py`)
1. **Model 1 — URL Risk Classifier (`src/train.py`)**: Evaluate Logistic Regression, Decision Tree, Random Forest, HistGradientBoosting, and XGBoost using domain-grouped CV + held-out domain-grouped test set; log Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, FPR, FNR, and Confusion Matrix.
2. **Model 2 — DOM Behaviour Classifier (`src/train_dom.py`)**: Train separate Random Forest, XGBoost, and GradientBoosting models on `data/processed/dom_dataset.csv` (`PhreshPhish` HTML + verified HTML fixtures) with domain-grouped split + temporal split validation.
3. **Model 3 — Brand Impersonation Detector (`src/features.py` / `backend/risk_engine.py`)**: Damerau/Levenshtein edit distance, homoglyph/Punycode check, character similarity, claimed-brand vs domain mismatch (never using brand name alone as proof).
4. **Model 4 — Credential & Payment Risk Detector**: Evaluates external credential submission, HTTP password forms, cross-domain payment actions, sensitive payment inputs, and upfront-payment scam signals.
5. **Model 5 — Threat Intelligence Engine (`backend/intel.py`)**: OpenPhish, HaGeZi Fake/TIF, CERT.pl, Phishing.Database, plus graceful PhishTank/URLhaus adapters with TTL cache, timeouts, and failure safety. Absent from feeds != safe.
6. **Versioned Model Artifacts (`src/model_registry.py`)**: Save model binary, feature columns, preprocessing pipeline/encoders, semantic version (`v2.0.0`), evaluation metrics, training date, and dataset lineage in `models/registry/<version>/` + active pointer in `models/`.

### Phase 5: Hybrid Risk Fusion Engine (`backend/risk_engine.py`)
- Fuse URL model, DOM model, Brand Impersonation, Credential/Payment risk, Deceptive behaviour, Threat Intelligence, Transport/HTTPS security, Redirect analysis, and Domain reputation.
- Output **non-arbitrary risk levels** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN`) and **6 separated assessment dimensions**:
  1. `connection_security`
  2. `phishing_risk`
  3. `malware_risk`
  4. `credential_risk`
  5. `payment_risk`
  6. `deceptive_behavior_risk`
- Explicitly avoid presenting heuristic fusion scores as statistically calibrated probabilities, avoid equating HTTP alone with phishing, avoid equating ads alone with malware, and avoid equating firewall blocks with malware.

### Phase 6: FastAPI Backend & SSRF Security (`backend/security.py`, `backend/main.py`, `backend/schemas.py`, `backend/explainer.py`, `backend/predictor.py`)
- **`backend/security.py`**: SSRF protection (block loopback, private, link-local, multicast, reserved, cloud metadata IPs via pre-connect DNS resolution & post-redirect IP validation; allow only `http`/`https`; cap redirects `<= 3`; cap response size `<= 2 MB`; strict timeouts), input sanitization, credential-stripping guard, and in-memory sliding-window rate limiter.
- **Endpoints**:
  - `GET /health`, `GET /version`, `GET /model-info`, `GET /analytics`
  - `POST /predict` (backward-compatible Chrome extension response + rich `assessment` field)
  - `POST /analyze-url`, `POST /analyze-dom`, `POST /analyze-website`, `POST /scan`, `GET /scan`
  - `POST /explain` (Groq + SHAP/feature-importance + rule-based per-dimension explanations)
  - `POST /feedback` + `GET /feedback` (safe quarantine storage in `data/feedback/reports.jsonl` — never auto-promotes unverified labels to training data)
- Fix CORS (`allow_credentials=False` or explicit extension/dev origins), payload limits, and structured logging.

### Phase 7 & 8: Chrome Extension Upgrade & UI/UX Redesign (`chrome_extension/`)
- Keep Manifest V3 & minimal permissions (`activeTab`, `scripting`, `storage`, `tabs`, `notifications`).
- **`content.js`**: Extract full URL + separated DOM behaviour features (`dom_features` matching `src/dom_features.py`), debounce SPA changes, never read password values/cookies/tokens, disclose unavailable cross-origin iframe checks, render nuanced risk-level warning banner (no silent blocking unless user enables it).
- **`background.js`**: Configurable `API_BASE_URL` stored in `chrome.storage.local` (supports production HTTPS URL + local dev default), domain/URL TTL cache, throttling, deduplication, backend `/health` connectivity check, scan history persistence (max 100 local entries, clearable), user-confirmed trusted domains list, and `/feedback` submission. Remove direct Groq key calls from extension code.
- **`popup.html` / `popup.css` / `popup.js`**: Modern cybersecurity dashboard with Dark/Light theme toggle, backend status badge, 6 separated risk dimension cards, expandable evidence & AI explanation drawer, "Trust Domain (Confirmed)" & "Report False Positive / Missed Threat" controls, local scan history drawer, and API endpoint configuration in Settings.

### Phase 9: MLOps, Docker & CI/CD
- Integrate **MLflow** tracking & local model registry logging inside `src/train.py`, `src/train_dom.py`, and `src/model_registry.py` with promotion gates (`F1 >= 0.90`, `ROC-AUC >= 0.94`, `FPR <= 0.05` on domain-grouped test).
- Add `Dockerfile`, `docker-compose.yml` (FastAPI + optional MLflow service), `.env.example`, updated `render.yaml`, updated `requirements.txt`, and `.github/workflows/ci.yml` (pytest + linting + model/API smoke checks).

### Phase 10: Comprehensive Testing & Complete Documentation
- **`tests/`**: Synthetic HTML/URL test suites (never hitting live malicious sites in automated tests!) covering URL features, DOM features, Brand Impersonation, Risk Engine rules (verifying HTTP != phishing, ads != malware, firewall != malware), SSRF protection, FastAPI endpoints, backend offline/timeout fallbacks, and Node/JS extension validation checks.
- **Documentation**: Rewrite `README.md` (all 20 required sections) and create all 7 docs under `docs/`: `architecture.md`, `dataset_documentation.md`, `model_documentation.md`, `api_documentation.md`, `extension_documentation.md`, `deployment.md`, and `privacy_and_security.md`.

