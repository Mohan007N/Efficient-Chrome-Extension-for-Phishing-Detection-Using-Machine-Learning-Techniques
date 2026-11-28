# WebShield AI v3.0 — Security Architecture & Controls Report

## 1. Summary of Security Hardening Implemented in v3.0

| Control Area | Module(s) | Implemented Guarantee |
| --- | --- | --- |
| **Explicit Class Index Resolution** | `src/evaluate.py`, `backend/predictor.py`, `backend/explainer.py` | Dynamically inspects `model.classes_` (`0 = Phishing/Malicious`, `1 = Benign/Legitimate`). Fails model load on invalid/missing classes; unwraps `CalibratedClassifierCV` for SHAP direction correctness. |
| **Separated Probability vs Heuristics** | `backend/risk_engine.py`, `backend/predictor.py`, `backend/schemas.py` | Strictly separates ML `phishing_probability` (`null` when unavailable/local) from `heuristic_risk_index` (`0–100`) and `connection_security`. |
| **No Trust / Whitelist Bypass** | `backend/predictor.py`, `backend/risk_engine.py`, `chrome_extension/background.js`, `chrome_extension/content.js` | Removed `is_whitelisted -> 0.02` overrides, `not is_whitelisted` deep-scan skips, and persistent `Trust Site` warning suppression. |
| **Multi-Tenant Hosting Isolation** | `src/features.py`, `backend/intel.py` | Offline PSL parsing (`tldextract` with private suffixes + non-PSL fallback for `.invalid`/`.test`) plus explicit `HOSTED_USER_CONTENT_SUBDOMAINS` checks prevent `sites.google.com` or `storage.googleapis.com` from inheriting provider immunity. |
| **Anti-DNS-Rebinding Fetcher** | `backend/security.py`, `src/web_forensics.py` | Resolves public DNS once per hop and pins TCP sockets directly to the validated public IP (`_PinnedHTTPConnection` / `_PinnedHTTPSConnection`) while enforcing strict TLS SNI + certificate verification. |
| **Gzip-Bomb & Concurrency Caps** | `backend/security.py` | Streaming chunk reads + `zlib.decompressobj` decompressed byte caps (`2.5 MB`), `1.5 MB` compressed ceiling, redirect depth cap (`<= 3`), and bounded `OUTBOUND_FETCH_SEMAPHORE`. |
| **Static Fetch & Extension DOM** | `backend/security.py`, `src/dom_features.py`, `chrome_extension/content.js` | Server-side optional HTML checks use SSRF-safe `safe_fetch_html()` + `lxml` without executing untrusted JS or shipping a headless browser binary; client-side inspection uses synchronized PSL brand checks, Shannon entropy JS scoring, SPA route watchers, and sliding-window MutationObserver throttling. |
| **CORS, Auth, Payload & Rate Limiting** | `backend/main.py`, `backend/security.py` | `STRICT_CORS=1` excludes wildcard `*`; `2 MB` body cap (`413`) enforced over streamed chunks (blocks chunked `Transfer-Encoding` bypasses); optional constant-time `WEBSHIELD_API_KEY` gate (`401`); URL query-parameter redaction before `/feedback` storage; idle-evicting & optional Redis-backed `RateLimiter` (`429`); sanitized 422/500 responses with zero tracebacks. |
| **Local Network Honest Status** | `backend/risk_engine.py`, `chrome_extension/background.js` | Localhost and private IP targets report `overall_risk_level = UNKNOWN` and `operational_status = LOCAL_NETWORK_UNVERIFIED` (never `LOW` / safe). |
| **Extension XSS & Cache Security** | `chrome_extension/utils.js`, `chrome_extension/content.js`, `chrome_extension/popup.js`, `chrome_extension/background.js` | Escapes all rendered DOM/evidence text (`escapeHtml`); keys caches by `cache_v3::<backendUrlTag>::<modelVersion>::<normalizedUrl>::<domFingerprint>`; isolates `cachedModelVersions` per backend URL; invalidates on `tabs.onUpdated`, SPA `pushState`/`replaceState`, & sliding `MutationObserver`; never accesses cookies, form input `.value`, or embedded secrets. |
| **Artifact Registry Integrity** | `src/model_registry.py`, `backend/predictor.py` | Full SHA-256 checksum verification across all bundle artifacts (`model`, `feature_columns`, `encoders`), validation-only promotion gates, atomic promotion via `os.replace()`, rollback support, and honest `/health` degraded reporting on integrity or feed failure. |

---

## 2. Automated Security Test Verification

Verified cleanly in [`tests/test_security_v3.py`](../tests/test_security_v3.py), [`tests/test_backend_api.py`](../tests/test_backend_api.py), [`tests/test_risk_engine.py`](../tests/test_risk_engine.py), [`tests/test_ml_pipeline_v3.py`](../tests/test_ml_pipeline_v3.py), and [`tests/test_extension_assets.py`](../tests/test_extension_assets.py):

- DNS rebinding simulated private-IP resolution rejection (`SSRFBlockedError`)
- Gzip-bomb compressed payload decompressed-limit enforcement (`PayloadTooLargeError`)
- SSRF blocks on `127.0.0.1`, `localhost`, `169.254.169.254`, `10.0.0.1`, `file://`, `ftp://`, and URL userinfo (`user:pass@...`)
- Strict CORS wildcard stripping under `STRICT_CORS=1`, idle-key eviction inside bounded `RateLimiter`, and recursive credential/cookie/CVV stripping in telemetry sanitization
- Streaming `> 2 MB` payload rejection (`413`) on chunked bodies, optional `WEBSHIELD_API_KEY` constant-time auth (`401`/`200`), and query-param redaction on `/feedback` logs
- Full SHA-256 tamper detection (including `feature_columns` & `encoders`), validation-only promotion gating, model class-mapping failure detection, malformed JSON 422 sanitization, Chrome Extension `utils.js` XSS escaping & `backendUrl`-scoped DOM fingerprint cache invalidation via Node runtime

