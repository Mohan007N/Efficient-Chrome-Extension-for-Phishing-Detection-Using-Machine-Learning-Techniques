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
| **Playwright Route Interception** | `src/playwright_inspector.py` | Ephemeral non-persistent browser contexts attach `page.route` blocking non-HTTP(S) schemes, `127.0.0.1`, RFC1918 networks, and cloud metadata endpoints (`169.254.169.254`). |
| **CORS, Payload & Rate Limiting** | `backend/main.py`, `backend/security.py` | `STRICT_CORS=1` excludes wildcard `*`; `2 MB` body cap (`413`); idle-evicting & optional Redis-backed `RateLimiter` (`429`); sanitized 422/500 responses with zero tracebacks. |
| **Local Network Honest Status** | `backend/risk_engine.py`, `chrome_extension/background.js` | Localhost and private IP targets report `overall_risk_level = UNKNOWN` and `operational_status = LOCAL_NETWORK_UNVERIFIED` (never `LOW` / safe). |
| **Extension XSS & Cache Security** | `chrome_extension/utils.js`, `chrome_extension/content.js`, `chrome_extension/popup.js`, `chrome_extension/background.js` | Escapes all rendered DOM/evidence text (`escapeHtml`); keys caches by `cache_v3::<modelVersion>::<normalizedUrl>::<domFingerprint>`; invalidates on `tabs.onUpdated` & `MutationObserver`; never accesses cookies, form input `.value`, or embedded secrets. |
| **Artifact Registry Integrity** | `src/model_registry.py`, `backend/predictor.py` | SHA-256 verification of promoted models, atomic promotion via `os.replace()`, rollback support, and honest `/health` degraded reporting on integrity or feed failure. |

---

## 2. Automated Security Test Verification

Verified cleanly in [`tests/test_security_v3.py`](../tests/test_security_v3.py), [`tests/test_backend_api.py`](../tests/test_backend_api.py), [`tests/test_risk_engine.py`](../tests/test_risk_engine.py), [`tests/test_ml_pipeline_v3.py`](../tests/test_ml_pipeline_v3.py), and [`tests/test_extension_assets.py`](../tests/test_extension_assets.py):

- DNS rebinding simulated private-IP resolution rejection (`SSRFBlockedError`)
- Gzip-bomb compressed payload decompressed-limit enforcement (`PayloadTooLargeError`)
- SSRF blocks on `127.0.0.1`, `localhost`, `169.254.169.254`, `10.0.0.1`, `file://`, `ftp://`, and URL userinfo (`user:pass@...`)
- Strict CORS wildcard stripping under `STRICT_CORS=1`, idle-key eviction inside bounded `RateLimiter`, and recursive credential/cookie/CVV stripping in telemetry sanitization
- Playwright request filter rejection of loopback, cloud metadata, and `file://` targets
- SHA-256 tamper detection, model class-mapping failure detection, malformed JSON 422 sanitization, Chrome Extension `utils.js` XSS escaping & DOM fingerprint cache invalidation via Node runtime

