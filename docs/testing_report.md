# WebShield AI v3.0 — Automated Testing & Scenario Verification Report

All checks below ran after the final code, dataset, model, and extension edits. Zero tests were skipped, relaxed, or mocked to suppress failures.

---

## 1. Automated Pytest Suite (`59 / 59 Passed`)

| Suite File | Tests | Scope | Execution Mode |
| --- | ---: | --- | --- |
| [`tests/test_url_features.py`](../tests/test_url_features.py) | 6 passed | PSL multi-part TLDs, `.invalid` fallback, `sites.google.com` hosting isolation, 33 URL features, brand similarity, `www.` canonicalization | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_dom_features.py`](../tests/test_dom_features.py) | 6 passed | First-party login, external credential POST, cross-origin iframes/scripts, obfuscated JS/fake downloads, prepaid checkout traps, SHA-256 DOM schema | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_risk_engine.py`](../tests/test_risk_engine.py) | 11 passed | HTTP != phishing, ads != malware, `UNKNOWN` without DOM/intel, threat intel criticality, `LOCAL_NETWORK_UNVERIFIED`, whitelist non-override, TLS error, firewall `Blocked`, empty DOM `{}` rejection, model thresholds, Amazon query tempering | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_extension_assets.py`](../tests/test_extension_assets.py) | 3 passed | MV3 minimal permissions, zero secret/cookie/trust-bypass code, sliding mutation throttle, SPA URL tracking, Node `chrome_extension/utils.js` unit verification | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_ml_pipeline_v3.py`](../tests/test_ml_pipeline_v3.py) | 4 passed | `model.classes_` ordering invariance, validation threshold tuning (`pos_label=0`), PSL domain-grouped splits & conflict priority, validation-only promotion gate & SHA-256 tamper/rollback | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_scenarios_v3.py`](../tests/test_scenarios_v3.py) | 15 passed | All **14 core safety scenarios** (official Amazon, first-party Google login, Razorpay checkout, `medium.com`/`sites.google.com` evidence-only evaluation, `.example` synthetic lookalike, insecure HTTP, empty DOM `{}` rejection, missing threat intel, known malicious feed `CRITICAL`, compromised `amazon.in` DOM escalation, multi-tenant subdomain isolation, unknown domain caution, SSRF/redirect detection, `schema_mismatch` rejection) + Chrome Extension Developer Diagnostics UI panel checks | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_security_v3.py`](../tests/test_security_v3.py) | 7 passed | Anti-DNS-rebinding resolver pinning, gzip-bomb decompression caps, `STRICT_CORS=1`, idle-evicting `RateLimiter`, credential stripping, Playwright complete removal, query redaction, constant-time `WEBSHIELD_API_KEY`, separated intel cache | Sandboxed (`BypassSandbox: false`) |
| [`tests/test_backend_api.py`](../tests/test_backend_api.py) | 7 passed | FastAPI lifespan & endpoints (`/health`, `/version`, `/model-info`, `/analytics`, `/predict`, `/analyze-url`, `/analyze-website`, `/analyze-dom`, `/scan`, `/explain`, `/feedback`), SSRF blocking, `422` malformed JSON, chunked `>2 MB` `413` limit, `WEBSHIELD_API_KEY` `401`/`200` | Unsandboxed (`BypassSandbox: true` for AnyIO `socketpair()`) |

**Total:** **`52 passed in 24.68s`** (sandboxed) + **`7 passed in 54.15s`** (API suite) = **`59 / 59 Passed (0 failed, 0 skipped)`**.

---

## 2. Dataset, CLI, Benchmark & Extension Checks

- **Dataset Validation (`python scripts/validate_dataset.py`):** `status: ok` — `verified_domains.csv` (`115` rows, `0` null cells, `{1: 88, 2: 26, 3: 1}`), `phishing_domains.csv` (`3,800` rows, `0` duplicates), `synthetic_lookalikes.csv` (`10` `.example` rows), `multiclass_dataset.csv` (`67,347` rows across Labels `0..4`), `url_splits` (`38,709 / 8,931 / 11,892`, `disjoint: true`), `dom_splits` (`3,128 / 730 / 968` + `1,080` temporal, `disjoint: true`).
- **False-Positive & Lookalike Benchmark (`python scripts/evaluate_false_positives.py`):** Verified `303` non-hosted legitimate URLs across Categories A–G -> `3` false positives (`0.99%` FPR vs `8.68%` baseline), `9 / 9` Amazon URLs `LOW` / `Real (Legitimate)` (`raw_url_ml_mean_prob_on_legit = 0.0953`), `10 / 10` synthetic `.example` lookalikes flagged `CRITICAL`.
- **Predictor CLI (`python src/predict.py`):** Threat intel loaded in `0.94s`, `LightGBM` URL (`33 cols, thr=0.55`) & `DOM XGBoost` (`36 cols, thr=0.65`) loaded with `integrity_ok: True`, `errors: []`, sample phishing assessment `CRITICAL` (`ML Phishing Prob: 0.9019 | Heuristic Index: 93/100`).
- **Extension JavaScript Syntax (`node --check`):** `chrome_extension/utils.js`, `content.js`, `background.js`, `popup.js` -> exit `0`.

