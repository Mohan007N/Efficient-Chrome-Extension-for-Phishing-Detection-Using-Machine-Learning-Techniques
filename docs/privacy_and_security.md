# Privacy and Security Design

## 1. User Privacy Guarantees (Chrome Extension & Backend)
- **Zero Credential Collection**: `chrome_extension/content.js` inspects only form structure and input attribute metadata (`type`, `name`, `placeholder`). It never accesses `.value` on password/text inputs, `document.cookie`, `localStorage`, or auth tokens.
- **Backend Payload Sanitization**: `backend/security.py:sanitize_telemetry_dict` strips any forbidden keys (`password`, `cookie`, `token`, `secret`, `cvv`, `card_number`, `pin`) before processing.
- **No Extension Secrets**: No Groq API keys or backend secrets are embedded in `chrome_extension/`.
- **Local-Only Scan History**: Scan history (capped at 100 items) stays inside browser `chrome.storage.local` and is user-clearable. Backend `/analytics` aggregates only anonymous counters.

## 2. SSRF Protection (`backend/security.py`)
When endpoints accept URLs for live backend fetching (`/analyze-url`, `/analyze-website`, `/scan`):
- Only `http://` and `https://` schemes are permitted.
- Embedded `user:pass@` URL credentials are rejected.
- DNS resolution is checked prior to connection; private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.169.254`), multicast, reserved, and unspecified (`0.0.0.0`) IPs are blocked.
- Automatic redirects are disabled and every redirect hop (`<= 3` max) is re-validated against SSRF IP rules.
- Response bodies are capped at `1.5 MB` with strict socket timeouts (`<= 6s`), and webpage JavaScript is **never** executed on the server.

## 3. API Security & Operational Controls
- Configurable CORS (`ALLOWED_ORIGINS`), avoiding wildcard `*` with `allow_credentials=True`.
- Request body ceiling (`2 MB`) and per-client sliding-window rate limiting (`RATE_LIMIT_PER_MIN`, HTTP `429`).
- User-submitted `/feedback` entries are quarantined in `data/feedback/reports.jsonl` (`pending_human_review`) to prevent label-poisoning attacks.

