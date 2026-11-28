# AI-Powered Website Safety, Phishing Detection & Trust Assessment System

> **WebShield AI v3.0.0** — Multi-Layer Website Safety, Phishing Detection & Trust Assessment Platform combining separated calibrated URL & DOM classifiers, PSL multi-tenant domain analysis, brand impersonation forensics, credential & payment risk detection, SSRF-pinned threat intelligence, SHAP Explainable AI, and an XSS-hardened Chrome Extension (Manifest V3).

---

## 1. Overview & Security Guarantees

Conventional phishing detectors collapse website safety into a simplistic binary label (`Legitimate` vs. `Phishing`) or confuse transport protocol/heuristic risk with calibrated machine learning probability. **WebShield AI v3.0.0** answers:

> *"Is this website safe to browse, log in, download files from, or make payments on?"*

with strict engineering guarantees:

- **Explicit Class Semantics:** `0 = Phishing / Malicious` (positive target) and `1 = Benign / Legitimate`, validated via `model.classes_` at load and inference time.
- **Calibrated ML Probability vs Heuristic Risk Index:** `phishing_probability` is a calibrated ML classifier output (or `null` when unavailable/local) — never synthesized from heuristics (`heuristic_risk_index` is separated cleanly).
- **Zero Test-Set Leakage:** Candidate selection, calibration (`CalibratedClassifierCV`), and threshold optimization use training/validation splits strictly partitioned by PSL registrable `root_domain`; held-out tests are evaluated once.
- **No Trust Blind Spots:** Reputation lists never skip deep scanning (`deep_scan`) and never override external credential harvesting, malicious DOM evidence, or threat feeds.
- **Multi-Tenant Hosting Isolation:** Uses Public Suffix List (`tldextract`) plus `HOSTED_USER_CONTENT_SUBDOMAINS` (`sites.google.com`, `storage.googleapis.com`, `*.vercel.app`) separation.
- **Honest Non-Binary States:** Loopback/private hosts return `LOCAL_NETWORK_UNVERIFIED` (`UNKNOWN` overall, `phishing_probability = null`); firewall/DNS sinkholes or unreachable hosts return `Blocked` or `Unreachable` without claiming safe or malware.

---

## 2. Six Separated Risk Dimensions

| Dimension | Signals Inspected | Key Safeguard |
| --- | --- | --- |
| **Connection Security** | HTTPS vs HTTP, mixed content, and strict X.509/TLS verification | Separates `SECURE_HTTPS`, `HTTPS_MIXED_CONTENT`, `INSECURE_HTTP`, `INVALID_CERTIFICATE`, `LOCAL_NETWORK_UNVERIFIED`, and `UNKNOWN`. |
| **Phishing Risk** | Calibrated URL ML (`LightGBM v3.0.0`), DOM ML (`DOM LightGBM v3.0.0`), PSL brand impersonation, active phishing feeds | Unknown domains missing DOM/intel evidence report `UNKNOWN` / `Insufficient evidence` instead of benign. |
| **Malware Risk** | Malware feeds (URLhaus / HaGeZi TIF), fake download/update CTAs, obfuscated/dynamic script injection | Standard third-party ads/analytics scripts alone never flag malware. |
| **Credential Risk** | Password/login forms, unencrypted login POSTs, cross-domain form targets, brand-domain mismatches | Legitimate first-party HTTPS login portals are not flagged solely for containing password fields. |
| **Payment Risk** | External payment skimmers, prepaid-only stores with restrictive/store-credit terms, missing corporate identity, fraud catalogs | Surfaces deceptive e-commerce/prepaid trap storefronts alongside credential threats. |
| **Deceptive Behaviour Risk** | Hidden/zero-size iframes, meta/JS redirects, `window.open` popups, notification prompts, urgency CTAs | Discloses uninspected cross-origin iframes and browser-opaque signals transparently. |

---

## 3. System Architecture (v3.0.0)

```text
[Chrome Extension MV3 v3.0 (chrome_extension/)]
 ├── utils.js           -> HTML XSS escaping, URL cache normalization, DOM fingerprinting, char stats
 ├── content.js         -> Structural DOM/URL metadata + throttled MutationObserver + safe banners
 ├── background.js      -> Model/DOM-versioned cache keys, tabs.onUpdated invalidation, no Trust bypass
 └── popup.html/css/js  -> Separated ML Phish Prob vs Heuristic Risk Index, LOCAL_NETWORK_UNVERIFIED/OFFLINE
          │
          ▼ HTTP/HTTPS JSON (zero passwords/cookies/API keys stored or sent by extension)
[Hardened FastAPI Backend v3.0.0 (backend/)]
 ├── security.py        -> IP-pinned HTTP/HTTPS connections (anti-DNS-rebinding), streamed gzip-bomb cap,
 │                         bounded outbound fetch Semaphore, strict CORS, optional API key, idle-evicting/Redis RateLimiter
 ├── main.py            -> Lifespan model + SHA-256 verification, async thread offload, streaming 2MB body cap, PII redaction
 ├── predictor.py       -> Validates full SHA-256 artifact checksums, model.classes_, calibrated thresholds & SSRF static fetch
 ├── intel.py           -> Separated domain vs URL cache, feed freshness TTL, reliability ratings, degraded error reporting
 ├── risk_engine.py     -> Calibrated threshold fusion -> LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN + operational_status
 └── explainer.py       -> Calibrated-unwrapped SHAP TreeExplainer + deterministic rules + optional Groq XAI
```

Architecture details: [`docs/v3_architecture.md`](docs/v3_architecture.md)

---

## 4. Repository Layout

```text
├── backend/
│   ├── main.py                # FastAPI v3.0.0 endpoints, CORS, payload limit, rate limiter, degraded health
│   ├── predictor.py           # SHA-256 & classes_-validated URL/DOM orchestrator + /predict bridge
│   ├── risk_engine.py         # 6-dimension HybridRiskEngine (no whitelist/local false-safe overrides)
│   ├── explainer.py           # Calibrated-unwrapped SHAP TreeExplainer + rule + optional Groq XAI
│   ├── intel.py               # Threat intel engine (timestamps, TTL, reliability, catalog cache)
│   ├── schemas.py             # Pydantic v2 v3.0 contracts
│   └── security.py            # Anti-DNS-rebinding pinned-IP HTTP/HTTPS client, gzip-bomb defense, CORS, RateLimiter
├── chrome_extension/
│   ├── manifest.json          # Manifest V3 v3.0.0 (minimal permissions)
│   ├── utils.js               # Shared XSS escapeHtml, URL cache key & DOM fingerprint helpers
│   ├── content.js             # DOM metadata extraction + MutationObserver + escaped banners
│   ├── background.js          # Version/DOM cache invalidation, LOCAL_NETWORK_UNVERIFIED/OFFLINE badges
│   ├── popup.html / .css / .js# Dark/Light UI separating ML Phishing Prob vs Heuristic Risk Index
│   └── icons/                 # Extension icons (16, 32, 48, 128 px)
├── src/
│   ├── build_datasets.py      # Multi-source dataset builder (PhiUSIIL, PhreshPhish Parquet, OpenPhish, Tranco)
│   ├── dataset_validation.py  # PSL domain-grouped splits, conflict priority, 18-category audit report
│   ├── features.py            # Model 1 (33 PSL-aligned URL features) + Model 3 (Brand impersonation)
│   ├── dom_features.py        # Model 2 (36 DOM features, single-pass lxml) + Model 4 (Credential/payment risk)
│   ├── web_forensics.py       # SSRF-routed storefront/TLS/RDAP forensics
│   ├── model_registry.py      # Atomic os.replace() model promotion, multi-artifact SHA-256 verification & rollback
│   ├── train.py / train_dom.py# Leak-free CV selection, calibration, validation thresholding & MLflow logging
│   ├── evaluate.py            # Explicit Phishing (0) & Benign (1) metrics, ROC/PR-AUC, FPR/FNR
│   └── predict.py             # CLI smoke runner
├── tests/                     # 43 automated pytest tests (URL, DOM, risk, ML pipeline, security, API, extension)
├── docs/                      # Architecture, Dataset, Model, API, Extension, Deployment & Privacy docs
├── reports/                   # v3 audit, dataset quality, model evaluation, security & test reports + CSVs
├── Dockerfile                 # FastAPI container bundling models & runtime intel snapshots
├── docker-compose.yml         # API service + optional MLflow UI profile
└── render.yaml / .github/workflows/ci.yml
```

---

## 5. Multi-Source Dataset Engineering (`v3.0`)

Source: [`reports/v3_dataset_quality_report.md`](reports/v3_dataset_quality_report.md)

- **URL Corpus (`data/processed/url_dataset.csv`):** `66,321` verified URLs across `64,374` unique PSL `root_domain`s (`33,242` Phishing `0` / `33,079` Benign `1`, `0` missing cells, `0` conflicts):
  - `phiusiil`: `59,930` | `phreshphish`: `5,995` | `openphish`: `300` | `tranco_vetted`: `78` | `custom_verified_fixture`: `18`
  - Domain-disjoint splits (`verify_domain_disjoint` = PASS): Train `43,079` | Val `9,954` | Held-Out Test `13,288`
- **DOM Corpus (`data/processed/dom_dataset.csv`):** `6,015` verified HTML documents across `5,534` unique PSL `root_domain`s (`3,009` Phishing `0` / `3,006` Benign `1`, parsed statically without executing JS):
  - Domain-disjoint splits: Train `3,128` | Val `730` | Held-Out Test `968` + Domain-Disjoint Chronological Temporal Test `1,080`
- **Quarantined Non-Binary Samples:** `520` unvetted Tranco candidates (`uncertain_samples.csv`) and `2` firewall/unreachable samples (`operational_status_samples.csv`) excluded from binary ML training.

---

## 6. Model Benchmarks & Active Registry (`v3.0.0`)

Detailed evaluation tables: [`reports/v3_model_evaluation_report.md`](reports/v3_model_evaluation_report.md)

- **Model 1 — URL Risk Classifier (`url_risk`, `XGBoost` + `CalibratedClassifierCV(sigmoid, domain-grouped cv=3)`, threshold = `0.44`):**
  - Untouched Held-Out Test (`n = 13,288`): Accuracy `0.9662` | Phishing Precision `0.9739` | Phishing Recall `0.9586` | **Phishing F1 `0.9662`** | Benign F1 `0.9662` | **ROC AUC `0.9901`** | **PR AUC `0.9926`** | **FPR `0.0261`** | FNR `0.0414`
- **Model 2 — DOM Behaviour Classifier (`dom_behavior`, `DOM XGBoost` + `CalibratedClassifierCV(isotonic, domain-grouped cv=5)`, threshold = `0.65`):**
  - Untouched Held-Out Test (`n = 968`): Accuracy `0.8729` | Phishing Precision `0.9112` | Phishing Recall `0.8418` | **Phishing F1 `0.8751`** | Benign F1 `0.8707` | **ROC AUC `0.9412`** | **PR AUC `0.9422`** | FPR `0.0921` | FNR `0.1582` (Val FPR `0.0673`)
  - Domain-Disjoint Temporal Split (`n = 1,080`): Accuracy `0.7565` | ROC AUC `0.8481` | PR AUC `0.8024` | FPR `0.0849`

Both bundles passed validation-only promotion gates (`Phishing F1 >= 0.85`, `ROC AUC >= 0.90`, `FPR <= 0.08`) and are registered with full SHA-256 verification in [`models/registry/active_manifest.json`](models/registry/active_manifest.json).

---

## 7. Quick Start & Automated Testing

```powershell
# 1. Setup & activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env

# 2. Rebuild v3.0 datasets & train/calibrate URL + DOM models
python src/build_datasets.py --max-phiusiil 60000 --max-phreshphish 6000
python run_train.py

# 3. Start FastAPI backend
uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 4. Run full v3.0 test suite (43 / 43 tests) & CLI smoke check
pytest -v tests/
python src/predict.py
```

Latest verified test & verification suite: **43 / 43 pytest tests passing** (`36` unit/DOM/risk/extension/ML/security tests + `7` FastAPI endpoint/SSRF/auth tests), `python src/predict.py` exit `0`, Playwright completely removed, and `node --check` on all extension scripts. Full reports: [`reports/v3_test_report.md`](reports/v3_test_report.md) | [`reports/v3_security_report.md`](reports/v3_security_report.md)
