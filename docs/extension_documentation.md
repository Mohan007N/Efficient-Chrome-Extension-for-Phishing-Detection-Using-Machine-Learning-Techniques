# Chrome Extension Documentation

## Overview (`chrome_extension/`)
Built on **Chrome Manifest V3** (`version: 2.0.0`) with minimal permissions (`activeTab`, `scripting`, `storage`, `tabs`, `notifications`).

## Components
- **`content.js`**:
  - Extracts URL features and structured DOM metadata across login forms, payment inputs, scripts, iframes, redirects, and misleading CTAs.
  - Debounces dynamic SPA URL updates (`700ms`) and deduplicates identical URLs within a session.
  - Counts cross-origin `<iframe>` elements and discloses them under `unavailable_signals` without claiming cross-origin inspection.
  - Displays a non-blocking safety notice banner for `MEDIUM`, `HIGH`, `CRITICAL`, or `UNKNOWN` assessments.
- **`background.js`**:
  - Uses configurable `api_base_url` from `chrome.storage.local` (defaults to `http://127.0.0.1:8000`; supports HTTPS production URLs).
  - Implements 5-minute TTL response caching, request throttling, and in-flight deduplication.
  - Stores up to `100` local scan history entries and user-confirmed `trusted_domains`.
  - Contains **no API keys or direct external LLM calls**.
- **`popup.html`, `popup.css`, `popup.js`**:
  - Dark & Light theme support.
  - Displays website domain, overall risk level (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`/`UNKNOWN`), Heuristic Risk Index, URL & DOM ML model outputs, 6 separated risk dimension badges, last scan timestamp, and backend connectivity pill (`Online`/`Offline`).
  - Expandable evidence & unavailable-signal disclosure, on-demand XAI reasoning (`Explain Verdict`), `Trust Site` confirmation, `Report False Positive` / `Report Threat` feedback, and local Scan History with `Clear History`.

## Loading in Chrome (Developer Mode)
1. Open `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `chrome_extension/` folder.
4. Click the extension gear icon (`⚙`) to configure your local or HTTPS production Backend API URL.

