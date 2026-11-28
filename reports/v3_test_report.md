# WebShield AI v3.0 — Automated Test & Verification Report

All checks below were executed after the final source, model, extension, and test edits. Zero tests were skipped, relaxed, or mocked to suppress genuine failures.

---

## 1. Automated Pytest Verification (`43 / 43 Passed`)

| Suite File | Scope | Result | Execution Mode |
| --- | --- | --- | --- |
| `tests/test_url_features.py` | PSL multi-part domains, non-PSL `.invalid` fallback, `sites.google.com` hosting isolation, v3 lexical features, brand impersonation, `www.` invariance | **6 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_dom_features.py` | First-party HTTPS login, external credential POST, cross-origin iframes/scripts, obfuscated JS/fake downloads, prepaid payment traps, DOM schema & SHA-256 | **6 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_risk_engine.py` | HTTP vs phishing separation, ads != malware, `UNKNOWN` without evidence, threat intel criticality, `LOCAL_NETWORK_UNVERIFIED`, whitelist non-override, `INVALID_CERTIFICATE`, firewall `Blocked` status, empty `{}` DOM rejection, loaded model thresholds | **10 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_extension_assets.py` | MV3 `3.0.0` minimal permissions, zero secret/cookie access, absence of persistent Trust bypass, SPA navigation & sliding mutation throttle, `backendUrl`-scoped cache keys, Node runtime execution of `chrome_extension/utils.js` (XSS, entropy, PSL compound TLD, brand mismatch) | **3 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_ml_pipeline_v3.py` | `model.classes_` ordering invariance (`[0,1]` vs `[1,0]`, missing class rejection), validation threshold tuning (`pos_label=0`), domain-grouped disjointness + conflict priority, validation-only promotion gate independence, multi-artifact SHA-256 tamper detection & rollback | **4 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_security_v3.py` | Anti-DNS-rebinding resolver pinning, gzip-bomb decompressed cap, `STRICT_CORS=1` wildcard rejection, idle-evicting `RateLimiter`, telemetry credential stripping, complete removal of `playwright`/`playwright_inspector`, query-param redaction, constant-time `WEBSHIELD_API_KEY`, separated domain vs page intel cache, honest failure reporting | **7 passed** | Sandboxed (`BypassSandbox: false`) |
| `tests/test_backend_api.py` | Live FastAPI lifespan load (`/health`, `/version`, `/model-info`, `/analytics`), SSRF URL blocks, malformed JSON clean `422`, `/predict` `LOCAL_NETWORK_UNVERIFIED` & separated scores, `/analyze-url`, `/analyze-website`, `/analyze-dom`, `/scan` GET/POST, `/explain` SHAP, `/feedback` query redaction, chunked `> 2 MB` `413` enforcement, optional `WEBSHIELD_API_KEY` `401`/`200` | **7 passed** (16.73s) | `BypassSandbox: true` (Windows sandbox blocks AnyIO `socketpair()`) |

**Totals:** `36 passed in 3.02s` (sandboxed offline suites) + `7 passed in 16.73s` (`test_backend_api.py`) = **43 / 43 passed (0 failed, 0 skipped)**.

---

## 2. CLI, Playwright Removal & Browser Extension Checks

- **Extension Manifest & JS Syntax (`json.tool` + `node --check`):** Verified `manifest.json`, `utils.js`, `content.js`, `background.js`, and `popup.js` -> `EXT_SYNTAX_OK` (`exit 0`).
- **Playwright Removal Check:** Confirmed `importlib.util.find_spec('playwright') is None` and `src/playwright_inspector.py` removed -> `PLAYWRIGHT_ABSENT_OK`.
- **End-to-End Predictor CLI (`python src/predict.py`):** Verified threat intel load (`0.36s`), full SHA-256 model/schema/encoder integrity & class validation (`CalibratedClassifierCV` URL `33 cols, thr=0.44`, DOM `36 cols, thr=0.65`), and separated verdict output (`ML Phishing Prob: 0.927 | Heuristic Index: 99/100`, `integrity_ok: True`, `errors: []`).
- **Container Note (`docker build`):** Docker CLI `29.7.2` could not connect to daemon (`//./pipe/docker_engine` unavailable in this environment — Docker Desktop daemon is not running), so container image build was not executed here.
