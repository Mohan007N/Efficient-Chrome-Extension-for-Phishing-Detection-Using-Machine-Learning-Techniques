# AI-Powered Website Safety, Phishing Detection & Trust Assessment System

> **Multi-Layer Website Risk Intelligence Platform (WebShield AI v2.0)** — Combining separated URL & DOM Machine Learning, Brand Impersonation Analysis, Credential & Payment Forensics, Threat Intelligence, SHAP Explainable AI, and a Privacy-First Chrome Extension (Manifest V3).

---

## 1. Overview & Motivation

Conventional phishing detectors collapse website safety into a simplistic binary label (`Legitimate` vs. `Phishing`) based heavily on raw URL text. That misses real-world web threats where a site may run over valid HTTPS yet run deceptive checkout scams, harvest credentials via cross-domain forms, abuse download lures, inject hidden iframes, or impersonate established shopping and banking portals.

Conversely, naive detectors often misclassify harmless unencrypted documentation (`http://`) as "phishing" or falsely equate advertising scripts or unreachable DNS/RDAP lookups with malware.

**WebShield AI** answers the practical user question:

> *"Is this website safe to browse, log in, download files from, or make payments on?"*

---

## 2. Threat Scope & Multi-Dimensional Assessment

Rather than forcing every website into one binary bucket, WebShield AI assesses **six separated risk dimensions** alongside transparent signal availability:

| Dimension | Signals Inspected | Key Safeguard |
| --- | --- | --- |
| **Connection Security** | HTTPS vs. HTTP transport and mixed-content count | HTTP alone indicates unencrypted transport (`MEDIUM`), never standalone proof of phishing. |
| **Phishing Risk** | Separated URL ML probability, DOM behaviour ML probability, brand impersonation, and active phishing feeds | Absence from a blocklist never implies safety (`UNKNOWN` when evidence is absent). |
| **Malware Risk** | Malware feeds (URLhaus / HaGeZi TIF), fake download/update buttons, and obfuscated/dynamic script injection | Standard third-party ads or scripts alone are never marked malware. |
| **Credential Risk** | Password/login forms, unencrypted login submission, external cross-domain form actions, and brand-domain mismatches | Legitimate first-party HTTPS login forms are not flagged solely for having password inputs. |
| **Payment Risk** | External payment processors, prepaid-only checkout with restrictive refund/store-credit clauses, absent corporate identity, and verified fraud registries | Designed to surface deceptive e-commerce/prepaid trap storefronts alongside credential threats. |
| **Deceptive Behaviour Risk** | Hidden/zero-size iframes, meta/JS redirects, `window.open` popups, notification permission prompts, and urgency CTAs | Discloses `cross_origin_iframes_uninspected` and unavailable browser signals honestly. |

Overall Risk Levels: **`LOW`** | **`MEDIUM`** | **`HIGH`** | **`CRITICAL`** | **`UNKNOWN`**.  
ML probabilities (`url_model_threat_probability`, `dom_model_threat_probability`) are reported separately from the multi-factor **`heuristic_risk_index` (`0–100`)**.

---

## 3. System Architecture

```text
[Chrome Extension MV3 (chrome_extension/)]
 ├── content.js         -> Structural DOM/URL extraction (0 credential values, 700ms SPA debounce)
 ├── background.js      -> Configurable API URL, 5-min TTL cache, throttle, local scan history (<=100)
 └── popup.html/css/js  -> Dark/Light themes, 6-dimension cards, XAI trigger, Trust Site, Feedback
          │
          ▼ HTTPS / JSON (never embeds API keys in extension)
[FastAPI Backend (backend/main.py)]
 ├── security.py        -> SSRF DNS/IP/redirect guard, 2 MB ceiling, rate limiter, privacy sanitizer
 ├── predictor.py       -> Loads promoted model registry bundles + orchestrates 5 assessment layers
 │    ├── Model 1: URL Risk Classifier        (src/features.py + models/url_model.pkl)
 │    ├── Model 2: DOM Behaviour Classifier   (src/dom_features.py + models/dom_model.pkl)
 │    ├── Model 3: Brand Impersonation        (edit distance, homoglyphs, Punycode, title mismatch)
 │    ├── Model 4: Credential & Payment Risk  (form action targets + storefront forensics)
 │    └── Model 5: Threat Intelligence Engine (backend/intel.py + unauthorized_domains.json.gz)
 ├── risk_engine.py     -> Multi-dimension fusion -> LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN
 └── explainer.py       -> SHAP TreeExplainer attributions + rule evidence + optional Groq synthesis
```

Detailed architectural notes: [`docs/architecture.md`](docs/architecture.md)

---

## 4. Repository Layout

```text
├── backend/
│   ├── main.py              # FastAPI REST endpoints, middleware, SSRF guards, lifespan loading
│   ├── predictor.py         # Multi-model orchestrator & backward-compatible /predict bridge
│   ├── risk_engine.py       # 6-dimension HybridRiskEngine (rule + ML fusion)
│   ├── explainer.py         # SHAP TreeExplainer + deterministic rules + optional Groq XAI
│   ├── intel.py             # Threat intelligence engine + Tranco ranking + safe forensics
│   ├── schemas.py           # Pydantic v2 request/response contracts
│   └── security.py          # SSRF IP/DNS/redirect validation, rate limiter, privacy sanitizer
├── chrome_extension/
│   ├── manifest.json        # Manifest V3 (minimal permissions, v2.0.0)
│   ├── content.js           # Safe DOM telemetry + non-blocking safety notice banner
│   ├── background.js        # Configurable API endpoint, cache, deduplication, trust/history store
│   ├── popup.html           # Redesigned Light/Dark multi-dimension security popup
│   ├── popup.css            # Dual-theme design system
│   ├── popup.js             # Controller: live status, XAI modal, Trust Site, feedback reporting
│   └── icons/               # Extension icons (16, 32, 48, 128 px)
├── src/
│   ├── build_datasets.py    # Multi-source dataset pipeline (PhiUSIIL, PhreshPhish, OpenPhish, Tranco)
│   ├── dataset_validation.py# Multi-label schema enforcement & domain-grouped GroupShuffleSplit
│   ├── features.py          # Model 1 (27 URL features, www.-canonicalized) + Model 3 (Brand detector)
│   ├── dom_features.py      # Model 2 (36 DOM features) + Model 4 (Credential & payment detector)
│   ├── web_forensics.py     # Safe static storefront forensics, DNS/TLS/RDAP helpers
│   ├── model_registry.py    # Versioned artifact registry & promotion gate verification
│   ├── train.py             # Model 1 training, domain-grouped CV, MLflow SQLite logging
│   ├── train_dom.py         # Model 2 training, domain-grouped + temporal evaluation, MLflow logging
│   ├── evaluate.py          # Metrics (Accuracy, F1, ROC-AUC, PR-AUC, FPR, FNR) & plots
│   ├── predict.py           # CLI verification script using PhishingPredictor
│   └── utils.py             # Logging & serialization helpers
├── tests/                   # Automated pytest suites (synthetic fixtures only)
├── docs/                    # Architecture, Dataset, Model, API, Extension, Deployment & Privacy docs
├── reports/                 # Initial audit, upgrade plan, feature inventory & comparison CSVs/plots
├── Dockerfile               # FastAPI container definition with /health check
├── docker-compose.yml       # API service + optional MLflow UI profile
├── render.yaml              # Render web service configuration
├── .github/workflows/ci.yml # Automated pytest, extension JSON/JS check & Docker build CI
└── requirements.txt         # Pinned runtime & MLflow/SHAP dependencies
```

---

## 5. Multi-Source Dataset Engineering

[`src/build_datasets.py`](src/build_datasets.py) integrates real and verified security sources without synthetic domain-label contamination:

- **PhiUSIIL** (`59,919` verified URLs after stripping prior `SYNTHETIC_PREFIXES` and capping at 2 rows per `root_domain`).
- **PhreshPhish** (`phreshphish/phreshphish`, Hugging Face CC-BY-4.0: `806` unique domain-capped HTML+URL records from `997` cached samples; parsed statically with BeautifulSoup — scripts are never executed).
- **OpenPhish** (`300` active phishing URLs).
- **Tranco Top-1M** (`72` vetted `TRUSTED_DOMAINS`; **417** unvetted top-ranked candidates isolated strictly into `data/processed/uncertain_samples.csv` with `binary_label = -1` so popularity alone never asserts safety).
- **Verified Multi-Label Fixtures** (`data/external/custom_verified.csv`: `8` verified consumer-fraud registry and offline HTML fixtures).
- **URLhaus & PhishTank** (optional API-key adapters; skip gracefully when unconfigured or rate-limited).

**Partitioning & Leakage Prevention (`src/dataset_validation.py`)**:
- `url_dataset.csv` (`61,105` rows across `58,401` unique root domains) -> domain-disjoint `url_train.csv` (`42,668`), `url_val.csv` (`6,129`), `url_test.csv` (`12,308`).
- `dom_dataset.csv` (`813` rows across `710` unique root domains) -> domain-disjoint `dom_train.csv` (`572`), `dom_val.csv` (`82`), `dom_test.csv` (`159`), plus chronological `dom_temporal_test.csv` (`202` rows).
- Large raw datasets (`dataset/*.csv`, `data/raw/`, `data/processed/`, `data/feedback/`) and `.env` secrets are excluded from Git tracking via `.gitignore`.

Full dataset documentation: [`docs/dataset_documentation.md`](docs/dataset_documentation.md)

---

## 6. Model Benchmarks & Active Registry

During evaluation, SHAP inspection revealed that `99.98%` of PhiUSIIL legitimate URLs began with `www.` compared with `60.4%` of benign PhreshPhish sites, causing naive URL models to assign spurious high risk (`~0.88`) to legitimate non-`www.` URLs. Leading `www.` prefixes are now canonicalized prior to lexical extraction in `src/features.py` so classifiers evaluate genuine structural risk.

### Model 1: URL Risk Classifier (`data/processed/url_test.csv` — `12,308` unseen domain-disjoint URLs)

| Model | CV F1 (Grouped) | Val F1 | Accuracy | Precision | Recall | F1 Score | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **HistGradientBoosting** *(Promoted `v2.0.0`)* | **0.9694** | 0.9696 | **0.9686** | 0.9538 | 0.9851 | **0.9692** | 0.9884 | **0.9917** | 0.0149 | 0.0478 |
| **XGBoost** | 0.9693 | **0.9698** | 0.9685 | 0.9541 | 0.9844 | 0.9690 | **0.9886** | 0.9916 | 0.0156 | 0.0475 |
| **Random Forest** | 0.9664 | 0.9697 | 0.9682 | **0.9543** | 0.9836 | 0.9687 | 0.9870 | 0.9908 | 0.0164 | **0.0472** |
| **Decision Tree** | 0.9621 | 0.9672 | 0.9638 | 0.9492 | 0.9800 | 0.9644 | 0.9808 | 0.9821 | 0.0200 | 0.0525 |
| **Logistic Regression** | 0.9489 | 0.9496 | 0.9482 | 0.9173 | **0.9854** | 0.9502 | 0.9781 | 0.9846 | **0.0146** | 0.0890 |

### Model 2: DOM Behaviour Classifier (`data/processed/dom_test.csv` — `159` unseen domain-disjoint pages + `202` temporal pages)

| Model | CV F1 (Grouped) | Val F1 | Temporal F1 | Accuracy | Precision | Recall | F1 Score | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **DOM Random Forest** *(Promoted `v2.0.0`)* | **0.8665** | **0.9455** | 0.9536 | **0.8365** | 0.8545 | **0.9038** | **0.8785** | **0.9030** | 0.8490 | **0.0962** | 0.2909 |
| **DOM HistGradientBoosting** | 0.8649 | **0.9455** | **0.9671** | 0.8302 | 0.8598 | 0.8846 | 0.8720 | 0.8939 | 0.8398 | 0.1154 | 0.2727 |
| **DOM XGBoost** | 0.8638 | **0.9455** | 0.9404 | 0.8302 | 0.8667 | 0.8750 | 0.8708 | 0.8976 | **0.8492** | 0.1250 | 0.2545 |
| **DOM GradientBoosting** | 0.8643 | 0.9259 | 0.9502 | 0.8239 | **0.8725** | 0.8558 | 0.8641 | 0.8993 | 0.8369 | 0.1442 | **0.2364** |

Both active bundles pass `src/model_registry.py` promotion gates (`F1 >= 0.82`, `ROC AUC >= 0.88`, `FPR <= 0.12`) and are recorded in [`models/registry/active_manifest.json`](models/registry/active_manifest.json).

Full model & XAI details: [`docs/model_documentation.md`](docs/model_documentation.md)

---

## 7. FastAPI Backend Endpoints

| Method & Path | Purpose |
| --- | --- |
| `GET /health` | Readiness status, URL/DOM model load state, feature counts, threat feed state |
| `GET /version` | API, URL model, DOM model, and schema versions |
| `GET /model-info` | Active model registry manifest & feed counts |
| `POST /predict` | Chrome Extension assessment endpoint (legacy compatible + full `assessment` breakdown) |
| `POST /analyze-url` | URL ML + Brand Impersonation + Threat Intel + optional SSRF-safe live fetch |
| `POST /analyze-dom` | Static HTML or structured `DOMFeaturesPayload` assessment |
| `POST /analyze-website` | Full combined URL + DOM + Redirect + Payment/Credential + Threat Intel evaluation |
| `POST` / `GET /scan` | Convenience SSRF-protected live scan endpoint |
| `POST /explain` | SHAP `TreeExplainer` attributions + rule breakdown + optional Groq LLM synthesis |
| `POST` / `GET /feedback` | Human-review feedback queue (`pending_human_review`; never auto-promoted) & aggregate counts |
| `GET /analytics` | Anonymized aggregate scan counts and risk distributions |
| `GET /unauthorized-sites` | Query built-in verified fraud/scam catalog |

Full API reference: [`docs/api_documentation.md`](docs/api_documentation.md)

---

## 8. Chrome Extension Setup (Manifest V3)

1. Open Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** ON.
3. Click **Load unpacked** and select [`chrome_extension/`](chrome_extension/).
4. Open the **WebShield AI** toolbar popup, click **`⚙`**, configure your local (`http://127.0.0.1:8000`) or HTTPS production backend URL, and click **Save**.
5. Browse any website to view its 6 risk dimension badges, Heuristic Risk Index, unavailable-signal disclosures, on-demand XAI explanations, `Trust Site` override, feedback reporting, and Dark/Light theme switcher.

Extension architecture & privacy guarantees: [`docs/extension_documentation.md`](docs/extension_documentation.md) & [`docs/privacy_and_security.md`](docs/privacy_and_security.md)

---

## 9. Quick Start (Local, Docker & Render)

### Local Development
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env

# Optional: rebuild processed datasets & retrain models
python src/build_datasets.py --max-phiusiil 60000 --max-phreshphish 1200
python src/train.py
python src/train_dom.py

# Start backend API (Swagger docs at http://127.0.0.1:8000/docs)
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### Docker & MLflow Tracking UI
```bash
docker compose up --build api
# Optional MLflow experiment UI (http://127.0.0.1:5000):
docker compose --profile mlops up --build
```

Deployment & environment reference: [`docs/deployment.md`](docs/deployment.md)

---

## 10. Automated Testing

All automated tests use synthetic HTML/URL fixtures (never visiting active malicious websites or mutating personal browsing state):

```powershell
# Unit, DOM, risk fusion, and Chrome extension security tests
pytest -v tests/test_url_features.py tests/test_dom_features.py tests/test_risk_engine.py tests/test_extension_assets.py

# FastAPI endpoint & SSRF test suite
pytest -v tests/test_backend_api.py
```

Latest verified test results: **20 / 20 tests passing** (`16` unit/extension tests + `4` backend API/SSRF tests) and `python src/predict.py` smoke check passing.

---

## 11. Known Limitations

- **Cross-Origin `<iframe>` Isolation**: Chrome content scripts and static HTML parsers cannot inspect documents inside cross-origin iframes (`cross_origin_iframes_uninspected` and `unavailable_signals` disclose this explicitly).
- **Runtime JS Obfuscation**: Static HTML analysis evaluates inline script entropy and DOM patterns without executing unknown JavaScript in a sandboxed browser engine.
- **RDAP / DNS & Feed Credentials**: Unreachable RDAP endpoints never imply malice (`unavailable_signals` notes missing `rdap_domain_age`). `URLHAUS_AUTH_KEY` and `PHISHTANK_API_KEY` are optional; unconfigured feeds degrade gracefully.
- **Historical Raw CSVs in Existing Git History**: `.gitignore` excludes `dataset/*.csv` going forward; previously committed large files remain in earlier Git history unless cleaned explicitly by the repository owner.

---

## 12. Documentation & Audit Reports

- **Architecture**: [`docs/architecture.md`](docs/architecture.md)
- **Datasets & Splits**: [`docs/dataset_documentation.md`](docs/dataset_documentation.md)
- **Models, Metrics & MLOps**: [`docs/model_documentation.md`](docs/model_documentation.md)
- **API Reference**: [`docs/api_documentation.md`](docs/api_documentation.md)
- **Chrome Extension Guide**: [`docs/extension_documentation.md`](docs/extension_documentation.md)
- **Deployment Guide**: [`docs/deployment.md`](docs/deployment.md)
- **Privacy & Security**: [`docs/privacy_and_security.md`](docs/privacy_and_security.md)
- **Audit & Planning Reports**: [`reports/initial_audit.md`](reports/initial_audit.md) | [`reports/upgrade_plan.md`](reports/upgrade_plan.md) | [`reports/feature_inventory.md`](reports/feature_inventory.md)
