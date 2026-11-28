# WebShield AI v3.0 — Threat Intelligence & Feed Governance

**Engine:** [`backend/intel.py`](../backend/intel.py) (`UnauthorizedIntelEngine`)  
**Feed Scripts:** [`scripts/update_threat_feeds.py`](../scripts/update_threat_feeds.py) & [`scripts/update_trusted_domains.py`](../scripts/update_trusted_domains.py)

---

## 1. Approved Intelligence Sources & Provenance

WebShield AI v3.0 relies strictly on approved, reproducible feeds and local compressed snapshots:

| Feed / Catalog | Signal Type | Storage Format | Cache / Refresh Behavior | Reliability |
| --- | --- | --- | --- | --- |
| **OpenPhish** | Active phishing URLs | `data/phishing_domains.csv` (live w/ `--fetch-live`, offline cache fallback) | `update_threat_feeds.py --fetch-live` | High |
| **PhreshPhish v3** | Verified HTML + URL phishing & benign corpus | `data/raw/phreshphish_v3_shards.parquet` | Read locally without live scraping | High |
| **PhiUSIIL** | Research phishing/legit URL benchmark | `dataset/PhiUSIIL_Phishing_URL_Dataset.csv` | Immutable raw dataset | Research Baseline |
| **Tranco Top-1M** | Popularity rank context (`tranco_rank`) | `dataset/tranco_top1m.json.gz` | Context signal only (never overrides DOM/threat hits) | Context Only |
| **Local Threat Registries** | Phishing/Malware/Scam (`URLhaus`, `CERT.pl`, `HaGeZi Fake/TIF`, `Phishing.Database`, `discovered_unauthorized_sites`) | `dataset/unauthorized_domains.json.gz` | Loaded into memory at startup; degraded status surfaced via `status_summary()` | High / Medium |
| **Verified Domain Seed Catalog** | Category A–G verified legitimate/third-party seeds | `data/verified_domains.csv` | Rebuilt by `update_trusted_domains.py`; optional `--verify-live` TLS checks | High |

**Non-Crawling Compliance:** Scripts never crawl unauthorized third-party websites, scrape search engines, or bypass Cloudflare/CAPTCHAs. Optional live reachability (`--verify-live`) and backend `fetch_live` only fetch explicitly requested targets through `validate_safe_url_and_resolve()`.

---

## 2. SSRF & DNS-Rebinding Protection (`backend/security.py`)

- Every outbound HTTP/HTTPS connection first resolves DNS via `validate_safe_url_and_resolve()`.
- Loopback (`127.0.0.0/8`, `::1`), RFC-1918 private (`10/8`, `172.16/12`, `192.168/16`), link-local/cloud metadata (`169.254.0.0/16`), CGNAT, and multicast ranges raise `SSRFBlockedError`.
- Resolved IPs are pinned directly to outbound connections (preventing TOCTOU DNS rebinding) behind an `asyncio.Semaphore` concurrency bound and streamed 2 MB / gzip-bomb decompression caps.

---

## 3. Separated Caching & Multi-Tenant Rules

- **Domain vs. Page Cache Isolation:** Domain-level metadata (`RDAP` domain age, TLS X.509 validation, `registry_match`, `tranco_rank`) caches by `root_domain`, whereas page-level HTML/forensics caches strictly by full normalized `url` (`test_intel_separates_domain_and_page_forensics_caches`).
- **Multi-Tenant Hosting Guard:** `UnauthorizedIntelEngine.is_trusted()` rejects all domains matching `is_hosted_user_content_subdomain()` (`sites.google.com`, `*.github.io`, `*.vercel.app`, `medium.com`, `wordpress.com`, `wix.com`, `blogspot.com`, etc.).
- **Honest Failure Visibility:** Missing intelligence files or failed lookups set `degraded = True` and populate `status_summary()["errors"]`; `HybridRiskEngine` surfaces `UNKNOWN` / `THREAT_INTEL_UNAVAILABLE` rather than assuming benign safety.

