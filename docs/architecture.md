# System Architecture

## Overview
The **AI-Powered Website Safety, Phishing Detection & Trust Assessment System** uses a **multi-layer hybrid risk architecture** rather than a single binary URL classifier. It evaluates websites across URL lexical patterns, DOM behaviour, brand impersonation, credential/payment forms, transport security, redirects, and threat intelligence.

```
[Chrome Extension MV3]
   ├── content.js       (Extracts URL + sanitized structural DOM features; zero credentials)
   ├── background.js    (Configurable API URL, TTL cache, throttle, local scan history)
   └── popup.html/js    (6-dimension dashboard, Dark/Light UI, Trust & Feedback controls)
            │
            ▼ HTTPS / JSON
[FastAPI Backend (backend/main.py)]
   ├── security.py      (SSRF guard, redirect revalidation, rate limiter, privacy sanitizer)
   ├── predictor.py     (Multi-model inference coordinator)
   │     ├── Model 1: URL Risk Classifier        (src/features.py + models/url_model.pkl)
   │     ├── Model 2: DOM Behaviour Classifier   (src/dom_features.py + models/dom_model.pkl)
   │     ├── Model 3: Brand Impersonation        (edit distance, homoglyph, Punycode, mismatch)
   │     ├── Model 4: Credential & Payment Risk  (external forms, unencrypted login, payment traps)
   │     └── Model 5: Threat Intelligence Engine (backend/intel.py: OpenPhish, HaGeZi, CERT.pl, etc.)
   ├── risk_engine.py   (Fuses 6 separated dimensions -> LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN)
   └── explainer.py     (SHAP TreeExplainer attributions + rule breakdown + optional Groq LLM)
```

## Separated Risk Dimensions
1. **Connection Security**: HTTPS status and mixed-content count (HTTP alone is treated as transport insecurity, never standalone proof of phishing).
2. **Phishing Risk**: Combined signal from URL ML, DOM ML, Brand Impersonation, and phishing feeds.
3. **Malware Risk**: Threat feeds (URLhaus / HaGeZi TIF), executable download lures, and obfuscated/dynamic script injection (third-party ads alone are never treated as malware).
4. **Credential Risk**: Unencrypted password inputs, cross-domain credential actions, and brand-domain mismatches on login forms.
5. **Payment Risk**: Cross-domain payment destinations, prepaid-only/restrictive refund traps without verifiable business contacts, and verified scam storefronts.
6. **Deceptive Behaviour Risk**: Hidden iframes, meta/JS redirects, excessive popups, notification prompt lures, and misleading urgency CTAs.

