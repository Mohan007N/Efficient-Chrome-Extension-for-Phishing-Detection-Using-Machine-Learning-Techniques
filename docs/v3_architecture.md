# WebShield AI v3.0 — System Architecture & Security Design

## 1. Design Principles

WebShield AI v3.0 separates **statistical machine learning probabilities** from **multi-factor heuristic risk signals**, **transport security**, and **operational reachability states**:

- **Explicit Class Semantics:** `0 = Phishing / Malicious` (positive target), `1 = Benign / Legitimate`. Every loaded or evaluated estimator resolves `model.classes_` at load and inference time (`src/evaluate.py -> resolve_class_indices`), rejecting missing or invalid class mappings.
- **No Probability Fabrication:** `phishing_probability` is a calibrated ML output (`CalibratedClassifierCV`) or `null` when unavailable/local. `heuristic_risk_index` (`0–100`) is reported independently.
- **No Trust Blind Spots:** Established domains (`TRUSTED_DOMAINS`) never bypass deep inspection (`deep_scan`) and never override external credential harvesting, malicious DOM signals, or verified threat feeds.
- **Multi-Tenant PSL Awareness:** Public Suffix List domain parsing (`tldextract` with private suffixes enabled) isolates user-owned subdomains (e.g., `*.vercel.app`) and blocks hosted user-content services (e.g., `sites.google.com`, `storage.googleapis.com`) from inheriting provider trust.
- **Honest Non-Binary States:** Loopback/private hosts return `LOCAL_NETWORK_UNVERIFIED` (`UNKNOWN` overall, `phishing_probability = null`). Firewall-sinkholed or timed-out sites return `Blocked` or `Unreachable` operational statuses rather than benign verdicts or guessed malware labels.

---

## 2. Architecture Layers

```text
[Chrome Extension MV3 v3.0 (chrome_extension/)]
 ├── utils.js           -> HTML XSS escaping, URL cache normalization, DOM fingerprinting, char stats
 ├── content.js         -> Structural DOM/URL metadata extraction + throttled MutationObserver + safe banners
 ├── background.js      -> Model/DOM-versioned cache keys, navigation invalidation, no Trust bypass
 └── popup.html/css/js  -> Separated ML Phish Prob vs Heuristic Risk Index, LOCAL_NETWORK_UNVERIFIED/OFFLINE
          │
          ▼ HTTP/HTTPS JSON (zero cookies/passwords/API keys in extension)
[Hardened FastAPI Backend (backend/)]
 ├── security.py        -> IP-pinned HTTP/HTTPS connections (anti-DNS-rebinding), streamed gzip-bomb cap,
 │                         bounded outbound fetch Semaphore, strict CORS, idle-evicting/Redis RateLimiter
 ├── main.py            -> Lifespan model + integrity loading, /health degraded checks, /predict, /analyze-*
 ├── predictor.py       -> Validates SHA-256 registry integrity & model.classes_; orchestrates 5 detection layers
 ├── intel.py           -> Threat feeds with update timestamps, TTL expiry, reliability & catalog memory cache
 ├── risk_engine.py     -> Multi-dimension fusion -> LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN
 └── explainer.py       -> Calibrated-wrapper-unwrapped SHAP TreeExplainer + rule evidence + optional Groq XAI
```

---

## 3. Separated ML Training, Calibration & Atomic Registry Pipeline (`src/`)

1. **Multi-Source Verified Corpus (`src/build_datasets.py`, `src/dataset_validation.py`):**
   - Preserves read-only raw `dataset/PhiUSIIL_Phishing_URL_Dataset.csv` without synthetic template artifacts.
   - Integrates PhreshPhish Parquet shards (real timestamped HTML + URL pages parsed statically without executing JS) alongside OpenPhish, Tranco vetted vs unvetted quarantine (`uncertain_samples.csv`), and operational status fixtures (`operational_status_samples.csv`).
   - Resolves label conflicts conservatively and partitions strictly by PSL registrable `root_domain` into disjoint `train`, `val`, and held-out `test` splits (`StratifiedGroupKFold` / `GroupShuffleSplit`), plus chronological `dom_temporal_test.csv`.
2. **Leak-Free Selection & Calibration (`src/train.py`, `src/train_dom.py`):**
   - URL candidate suite (`LogisticRegression`, `RandomForest`, `HistGradientBoosting`, `XGBoost`, `LightGBM`) and DOM candidate suite (`RandomForest`, `ExtraTrees`, `GradientBoosting`, `XGBoost`).
   - Candidate ranking uses training-only group CV (`StratifiedGroupKFold`) + validation metrics **only**.
   - Fits probability calibration (`CalibratedClassifierCV`) strictly on training folds, tunes classification cutoff strictly on validation probabilities (`optimize_phishing_threshold`), and evaluates the single promoted model once on the untouched test split.
3. **Atomic Registry & Integrity (`src/model_registry.py`):**
   - Computes SHA-256 hashes over promoted model artifacts, feature schemas, encoders, and dataset lineage.
   - Verifies minimum security gates (`Phishing F1 >= 0.85`, `ROC AUC >= 0.90`, `FPR <= 0.08`) before atomically promoting via staging files + `os.replace()`.
   - Supports checksum verification on backend startup and instant rollback to prior registered releases.

---

## 4. Security & SSRF Controls

- **Anti-DNS-Rebinding Fetcher (`backend/security.py`):** Resolves DNS once per HTTP hop, rejects private/loopback/link-local/multicast/reserved IPs, and pins TCP socket connection directly to the validated public IP via custom `HTTPConnection` / `HTTPSConnection` handlers while preserving strict TLS SNI and hostname verification. Server-side optional live HTML inspection uses `safe_fetch_html()` + `lxml` static parsing (no headless browser dependency or JS execution), paired with live Chrome extension DOM extraction.
- **Gzip-Bomb Protection (`safe_decompress_gzip`):** Decompresses incrementally via `zlib.decompressobj` with hard compressed (`1.5 MB`) and decompressed (`2.5 MB`) limits.
- **Strict API Guardrails:** Configurable CORS (`STRICT_CORS=1` strips wildcard `*`), streaming request body cap (`2 MB` enforced across chunked & fixed requests), optional constant-time `WEBSHIELD_API_KEY` authentication (`X-API-Key` / `Authorization: Bearer`), query-parameter redaction before persisting `/feedback` logs, sanitized validation/exception responses (zero stack trace leakage), and idle-evicting / optional Redis-backed sliding-window rate limiting.

