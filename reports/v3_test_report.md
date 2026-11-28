# WebShield AI v3.0 — Automated Test & Verification Report

All checks below were executed after the final source and extension edits. Zero tests were skipped, relaxed, or mocked to suppress genuine failures.

---

## 1. Automated Pytest Verification (`38 / 38 Passed`)

| Suite File | Scope | Result | Execution Mode |
| --- | --- | --- | --- |
| `tests/test_url_features.py` | PSL multi-part domains, non-PSL `.invalid` fallback, `sites.google.com` hosting isolation, v3 lexical features, brand impersonation, `www.` invariance | **6 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_dom_features.py` | First-party HTTPS login, external credential POST, cross-origin iframes/scripts, obfuscated JS/fake downloads, prepaid payment traps, DOM schema & SHA-256 | **6 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_risk_engine.py` | HTTP vs phishing separation, ads != malware, `UNKNOWN` without evidence, threat intel criticality, `LOCAL_NETWORK_UNVERIFIED`, whitelist non-override, `INVALID_CERTIFICATE`, firewall `Blocked` status | **8 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_extension_assets.py` | MV3 `3.0.0` minimal permissions, zero secret/cookie access, absence of persistent Trust bypass, Node execution of `chrome_extension/utils.js` (XSS escaping, DOM fingerprint & model-version cache invalidation) | **3 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_ml_pipeline_v3.py` | `model.classes_` ordering invariance (`[0,1]` vs `[1,0]`, missing class rejection), validation threshold tuning (`pos_label=0`), domain-grouped disjointness + conflict priority, SHA-256 registry tamper detection & rollback | **4 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_security_v3.py` | Anti-DNS-rebinding resolver pinning, gzip-bomb decompressed cap, `STRICT_CORS=1` wildcard rejection, idle-evicting `RateLimiter`, telemetry credential stripping, Playwright SSRF route filter, honest threat-intel failure reporting | **5 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_backend_api.py` | Live FastAPI lifespan load (`/health`, `/version`, `/model-info`, `/analytics`), SSRF URL blocks, malformed JSON clean `422`, `/predict` `LOCAL_NETWORK_UNVERIFIED` & separated scores, `/analyze-website`, `/analyze-dom`, `/explain` SHAP, `/feedback` | **6 passed** (33.20s) | `BypassSandbox: true` (Windows sandbox blocks AnyIO `socketpair()`) |

**Totals:** `32 passed in 12.33s` (sandboxed offline suites) + `6 passed in 33.20s` (`test_backend_api.py`) = **38 / 38 passed (0 failed, 0 skipped)**.

---

## 2. CLI & Browser Extension Syntax Checks

- **Extension Manifest & JS Syntax (`json.tool` + `node --check`):** Verified `manifest.json`, `utils.js`, `content.js`, `background.js`, and `popup.js` -> `EXTENSION_SYNTAX_OK` (`exit 0`).
- **End-to-End Predictor CLI (`python src/predict.py`):** Verified threat intel load (`0.80s`), SHA-256 model integrity & class validation (`CalibratedClassifierCV` URL `33 cols`, DOM `36 cols`), and separated verdict output (`ML Phishing Prob: 0.8901 | Heuristic Index: 88/100`, `integrity_ok: True`, `errors: []`).

