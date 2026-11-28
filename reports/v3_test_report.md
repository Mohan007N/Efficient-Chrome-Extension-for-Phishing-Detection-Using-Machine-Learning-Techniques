# WebShield AI v3.0 — Automated Test & Verification Report

All checks below were executed after the final source, model, extension, and test edits. Zero tests were skipped, relaxed, or mocked to suppress genuine failures.

---

## 1. Automated Pytest Verification (`59 / 59 Passed`)

| Suite File | Scope | Result | Execution Mode |
| --- | --- | --- | --- |
| `tests/test_url_features.py` | PSL multi-part domains, non-PSL `.invalid` fallback, `sites.google.com` hosting isolation, v3 lexical features, brand impersonation, `www.` invariance | **6 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_dom_features.py` | First-party HTTPS login, external credential POST, cross-origin iframes/scripts, obfuscated JS/fake downloads, prepaid payment traps, DOM schema & SHA-256 | **6 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_risk_engine.py` | HTTP vs phishing separation, ads != malware, `UNKNOWN` without evidence, threat intel criticality, `LOCAL_NETWORK_UNVERIFIED`, whitelist non-override, `INVALID_CERTIFICATE`, firewall `Blocked` status, empty `{}` DOM rejection, loaded model thresholds, Amazon query tempering | **11 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_extension_assets.py` | MV3 `3.0.0` minimal permissions, zero secret/cookie access, absence of persistent Trust bypass, SPA navigation & sliding mutation throttle, `backendUrl`-scoped cache keys, Node runtime execution of `chrome_extension/utils.js` | **3 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_ml_pipeline_v3.py` | `model.classes_` ordering invariance, validation threshold tuning (`pos_label=0`), domain-grouped disjointness + conflict priority, validation-only promotion gate independence, multi-artifact SHA-256 tamper detection & rollback | **4 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_scenarios_v3.py` | All **14 safety scenarios** (Amazon, Google login, Razorpay, `medium.com`/hosted sites, `.example` lookalikes, HTTP transport, empty DOM `{}`, missing threat intel, malicious feed hit `CRITICAL`, compromised official domain escalation, multi-tenant subdomain isolation, unknown domain caution, SSRF/redirect detection, `schema_mismatch` rejection) + Extension Developer Diagnostics UI | **15 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_security_v3.py` | Anti-DNS-rebinding resolver pinning, gzip-bomb decompressed cap, `STRICT_CORS=1` wildcard rejection, idle-evicting `RateLimiter`, telemetry credential stripping, complete removal of `playwright`/`playwright_inspector`, query-param redaction, constant-time `WEBSHIELD_API_KEY`, separated domain vs page intel cache | **7 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_backend_api.py` | FastAPI lifespan load (`/health`, `/version`, `/model-info`, `/analytics`), SSRF URL blocks, malformed JSON `422`, `/predict` `LOCAL_NETWORK_UNVERIFIED` & separated scores, `/analyze-url`, `/analyze-website`, `/analyze-dom`, `/scan` GET/POST, `/explain` SHAP, `/feedback` query redaction, chunked `> 2 MB` `413`, `WEBSHIELD_API_KEY` `401`/`200` | **7 passed** (54.15s) | `BypassSandbox: true` (AnyIO `socketpair()`) |

**Totals:** `52 passed in 24.68s` (sandboxed offline suites) + `7 passed in 54.15s` (`test_backend_api.py`) = **59 / 59 passed (0 failed, 0 skipped)**.

---

## 2. CLI, Dataset Validation, False-Positive Benchmark & Extension Checks

- **Extension JS Syntax (`node --check`):** Verified `utils.js`, `content.js`, `background.js`, and `popup.js` -> exit `0`.
- **Dataset Integrity (`python scripts/validate_dataset.py`):** `status: ok`, `disjoint: true` across URL (`38,709 / 8,931 / 11,892`) & DOM (`3,128 / 730 / 968` + `1,080` temporal) splits, `multiclass_dataset.csv` `67,347` rows.
- **False-Positive Benchmark (`python scripts/evaluate_false_positives.py`):** `303` non-hosted legitimate URLs -> `0.99%` FPR (`3` FPs vs `27` baseline), `9 / 9` Amazon URLs `LOW`, `10 / 10` `.example` lookalikes `CRITICAL`.
- **End-to-End Predictor CLI (`python src/predict.py`):** Verified threat intel load (`0.94s`), `LightGBM` URL (`33 cols, thr=0.55`) & `DOM XGBoost` (`36 cols, thr=0.65`), `integrity_ok: True`, `errors: []`, verdict `CRITICAL` (`ML Phishing Prob: 0.9019 | Heuristic Index: 93/100`).
