# WebShield AI v3.0 — Phase 1 Codebase Audit Report

**Repository:** `https://github.com/Mohan007N/Efficient-Chrome-Extension-for-Phishing-Detection-Using-Machine-Learning-Techniques`  
**Baseline Version Audited:** `v2.0.0` (Commit `6beef22`)  
**Audit Scope:** `backend/`, `chrome_extension/`, `src/`, `models/`, `data/`, `dataset/`, `tests/`, `docs/`, `reports/`, `.github/`, `Dockerfile`, `docker-compose.yml`, `render.yaml`, `requirements.txt`, `README.md`, `.env.example`, `.gitignore`.

---

## Executive Summary

The v2.0 architecture cleanly separates URL vs. DOM features and enforces SSRF checks and privacy sanitization, **but full inspection revealed 18 concrete engineering, ML, security, caching, and deployment defects** that violate production reliability and security guarantees. Most critically:

1. **Test-set leakage in model selection:** Both `src/train.py` and `src/train_dom.py` sort candidate models by **test-set** F1/ROC-AUC (`X_test`, `y_test`) when picking the winner.
2. **Misrepresented ML probabilities & positive-class metric inversion:** `backend/predictor.py:283-288` sets `phishing_probability = heuristic_risk_index / 100.0`, confusing heuristic fusion with ML probability. Meanwhile, `src/evaluate.py:20-23` computes `Precision`, `Recall`, and `F1 Score` using scikit-learn's default `pos_label=1` (**Legitimate**), mislabeling benign F1 as headline F1, while `backend/predictor.py:153,164` hardcodes `predict_proba()[0]` without checking `model.classes_`.
3. **Security bypasses in Risk Engine & Chrome Extension:** `backend/risk_engine.py:176` forces `phish_score = 0.02` when `is_whitelisted`, `backend/predictor.py:213` disables `deep_scan` on whitelisted domains, `is_local` blindly returns `LOW` ("Safe local development environment"), and `chrome_extension/background.js:137-170` skips backend scanning completely on user-trusted domains.
4. **TOCTOU DNS rebinding, gzip bomb, and extension cache staleness:** `backend/security.py` resolves DNS separately before opening `urllib` (no IP pinning on socket) and calls `gzip.decompress(raw)` without an uncompressed-byte ceiling; `background.js:181` caches solely by raw URL without a DOM feature fingerprint or model version.
5. **Manual suffix list & standalone Docker gap:** `src/features.py` and `chrome_extension/content.js` parse domains with a small manual `compound_second_level` set instead of Public Suffix List (`tldextract`); `Dockerfile` omits runtime threat intelligence snapshots under `dataset/`.

---

## Detailed Findings Across All 18 Audit Areas

| # | Audit Category | Affected Files & Locations | Observed Defect | Severity |
| --- | --- | --- | --- | --- |
| 1 | **Runtime & DoS Bugs** | `backend/security.py:151-155`, `backend/intel.py:295-310`, `setup_and_run.bat` | `gzip.decompress(raw)` has no decompressed size ceiling (gzip bomb OOM risk). `search_catalog()` re-reads CSV from disk per request. `setup_and_run.bat` omits `requirements.txt`. | **High** |
| 2 | **Legacy & Unused Artifacts** | `models/feature_columns.pkl`, `models/label_encoder.pkl`, `src/clean_dataset.py`, `src/preprocessing.py` | Unused v1 artifacts remain alongside v2 models; legacy scripts contain older synthetic sample generators. | **Low** |
| 3 | **External Feed & Optional Lib Gaps** | `src/build_datasets.py:278-320`, `backend/explainer.py:192-200`, `src/web_forensics.py` | HuggingFace `/rows` API caps/errors with HTTP 500 at `offset=1000` (`split=train`) and `offset=0` (`split=test`), starving the DOM corpus at `813` rows. No LightGBM, `tldextract`, or SSRF-safe Playwright analyzer is integrated. | **High** |
| 4 | **Feature Mapping & PSL Deficiencies** | `src/features.py:191-208,371-446`, `chrome_extension/content.js:34-44,273,334-335` | `extract_root_domain` uses manual 7-entry suffix set instead of PSL (`tldextract`), misparsing `.co.jp`, `.com.au`, `.gov.uk`, `.github.io`, `.workers.dev`. `content.js` hardcodes `brand_domain_mismatch: 0`, `SpacialCharRatioInURL: 0`, `CharContinuationRate: 0`. Missing explicit `has_userinfo_in_url`, `has_redirect_indicator`, `special_char_ratio`. | **High** |
| 5 | **Class-Label Mapping Bugs** | `backend/predictor.py:153,164`, `backend/explainer.py:53-59`, `src/evaluate.py:180` | Inference indexes `predict_proba()[0]` and SHAP assumes `sv[0]` without mapping via `model.classes_`. No validation fails load if a required class (`0` or `1`) is absent. | **Critical** |
| 6 | **Model Loading & Health Readiness** | `backend/main.py:151-162`, `backend/predictor.py:67-98` | `/health` reports `"status": "ok"` whenever *any* one model loads, even when `dom_model` is missing or threat intelligence failed to load. No SHA-256 verification before loading pickles. | **High** |
| 7 | **Dataset Coverage & Provenance** | `src/build_datasets.py`, `data/processed/dom_dataset.csv` (`813` rows), `dataset/` | DOM dataset (`572` train, `82` val, `159` test) is too small and skewed (`551` benign vs `262` unsafe). Missing explicit operational state separation (`Malicious`, `Benign`, `Unknown`, `Unreachable`, `Blocked`, `Insufficient evidence`), full URL threat categories, content SHA-256 hashes, and collection-method provenance fields. | **High** |
| 8 | **Test-Set Selection Leakage** | `src/train.py:172`, `src/train_dom.py:172`, `src/evaluate.py` | Both training scripts sort and select best candidates on **test metrics** (`X_test`, `y_test`) instead of validation metrics; neither optimizes probability thresholds nor calibrates probabilities on validation data prior to a single untouched test evaluation. | **Critical** |
| 9 | **Incorrect Metric Positive Class** | `src/evaluate.py:20-45`, `reports/model_comparison_results.csv`, `reports/dom_model_comparison.csv` | `Precision`, `Recall`, and `F1 Score` compute metrics for `pos_label=1` (**Benign/Legitimate**) instead of explicitly reporting separate `Phishing` (`pos_label=0`) and `Benign` (`pos_label=1`) metrics. `DOM Random Forest` missed 29.1% of phishing (`FNR=0.2909`) while showing `F1 Score: 0.8785`. | **Critical** |
| 10 | **Inconsistent Response Schemas** | `backend/predictor.py:283-294`, `backend/schemas.py`, `backend/risk_engine.py:294-314` | `phishing_probability` in `/predict` equals `heuristic_risk_index / 100.0`; heuristic fallback invents `0.01` for `is_local` instead of returning `null` when ML isn't run; missing explicit `model_availability`, `confidence`, `assessment_status`, and structured `reasoning` fields. | **Critical** |
| 11 | **Chrome Extension Cache, Bypass & XSS** | `chrome_extension/background.js:137-192`, `content.js:395-404`, `popup.js:89,190,199` | Trusted-domain toggle completely skips scanning and suppresses critical alerts. Cache keys solely by `pageUrl` without DOM fingerprint or model version. No `MutationObserver` for dynamic DOM updates. Unescaped `innerHTML` string interpolation in banner and popup creates DOM-XSS risk. Missing `LOCAL_NETWORK_UNVERIFIED` & `OFFLINE` UX handling. | **Critical** |
| 12 | **Backend Security Gaps** | `backend/security.py:56-177`, `backend/main.py:108-132`, `src/web_forensics.py:146-158` | DNS resolution happens before `urllib.request.urlopen`, leaving TOCTOU **DNS rebinding** exposure (no IP pinning). No gzip bomb decompressed byte cap. `RateLimiter` lacks idle key eviction and distributed/shared store interface. `web_forensics.fetch_url_bytes` lacks SSRF guards. | **Critical** |
| 13 | **Deployment Reproducibility** | `Dockerfile:17-21`, `docker-compose.yml` | `Dockerfile` does not copy or generate runtime threat-intel snapshots (`unauthorized_domains.json.gz`, `tranco_top1m.json.gz`), causing standalone container builds to boot without threat feeds. | **High** |
| 14 | **Missing Dependencies** | `requirements.txt` | Missing `tldextract` (PSL), `lightgbm` (optional URL candidate), and optional `playwright` (sandboxed headless DOM analysis). | **Medium** |
| 15 | **Missing Artifacts & Entrypoints** | `run_train.py`, `docs/`, `reports/` | `run_train.py` runs `src/train.py` only; `setup_and_run.bat` points to outdated commands; v3 audit/quality/eval/security/test reports not yet generated. | **Medium** |
| 16 | **Documentation Lag** | `README.md`, `docs/*` | Current documentation describes `v2.0.0` endpoints and uncalibrated benign-label F1 benchmarks. | **Low** |
| 17 | **Registry & MLOps Deficiencies** | `src/model_registry.py:67-118` | Non-atomic `shutil.copy2` promotion; lacks SHA-256 artifact checksums, `class_mapping`, decision `threshold`, `val_metrics` vs `test_metrics` separation, `training_config`, `library_versions`, `dataset_fingerprint`, and rollback mechanism. | **High** |
| 18 | **Test Coverage Gaps** | `tests/` | Existing 20 tests lack checks for `classes_` order invariance, calibrated probability vs heuristic decoupling, validation-only selection/thresholding, `tldextract` PSL parsing, DNS rebinding / pinned IP, gzip bomb DoS, `LOCAL_NETWORK_UNVERIFIED`, trusted-domain non-suppression, stale DOM cache invalidation, CORS, malformed JSON, and rate limiting. | **High** |

---

## Verified Local Inventory (Pre-Change Snapshot)
- `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`: `71,710,795` bytes (`~292,106` rows) — **preserved untouched**.
- `dataset/tranco_top1m.json.gz`: `9,896,773` bytes (`1,000,000` domain ranks) — **preserved**.
- `dataset/unauthorized_domains.json.gz`: `8,407,251` bytes (`1,096,251` total entries across verified/HaGeZi/OpenPhish/CERT.pl/Phishing.Database/Scam-Blocklist) — **preserved**.
- `data/raw/phreshphish_sample.json.gz`: `26,398,687` bytes (`997` cached HTML+URL records).
- `models/`: `url_model.pkl` (`HistGradientBoostingClassifier`, `classes=[0, 1]`), `dom_model.pkl` (`RandomForestClassifier`, `classes=[0, 1]`), plus legacy `feature_columns.pkl` / `label_encoder.pkl`.

---

## Execution Roadmap (Phases 2–15)
Proceeding sequentially through:
1. Dependencies & PSL/Playwright/LightGBM verification (`requirements.txt`).
2. Dataset validation, expanded real HTML DOM collection, 18-category operational taxonomy, and `reports/v3_dataset_quality_report.md` (Phase 4 & 5).
3. Correct probability mapping, per-class metrics (`Phishing` vs `Benign`), leak-free validation-only selection, calibration, and threshold optimization (`src/evaluate.py`, `src/train.py`, `src/train_dom.py`, `src/model_registry.py` — Phases 2, 3, 11).
4. Safe Playwright/static DOM analyzer, SSRF-pinned socket/DNS rebinding + gzip-bomb protection, feed freshness & failure transparency, evidence-based `HybridRiskEngine` without whitelist/localhost bypasses (`backend/*`, `src/web_forensics.py` — Phases 6, 7, 8, 10).
5. Chrome Extension v3.0 DOM-fingerprinted caching, XSS-safe rendering, non-bypassing Trust preferences, and reliable UX (`chrome_extension/*` — Phase 9).
6. Comprehensive tests across all new guarantees, deployment fixes, full reports (`v3_*_report.md`, `docs/v3_architecture.md`, `README.md`), and clean commit proposal awaiting explicit user approval (Phases 12–15).

