# WebShield AI v3.0 — Dataset Documentation & Governance

**Generated Against Build:** `2026-11-28T14:26:30+00:00` (`reports/v3_dataset_quality_report.md`)

---

## 1. Multi-Source Architecture & Governance Rules

WebShield AI v3.0 combines verified legitimate web properties, multi-source phishing corpora, static DOM captures, and controlled synthetic test fixtures while strictly preventing label leakage and blind domain whitelisting:

- **Trusted Domains Are Not Blindly Exempted:** Known brand domains in `src/seed_catalog.py` / `data/verified_domains.csv` require verification (`https://` reachability or verified seed status in `src/seed_catalog.py`) before receiving `label = 1`, and compromised pages or cross-domain credential exfiltration still trigger `HIGH`/`CRITICAL`.
- **Multi-Tenant Platform Separation:** User-content and site-builder platforms (`MULTI_TENANT_HOSTING_PLATFORMS`: `github.io`, `vercel.app`, `netlify.app`, `pages.dev`, `blogspot.com`, `blogger.com`, `wordpress.com`, `wixsite.com`, `wix.com`, `squarespace.com`, `medium.com`, `substack.com`, `herokuapp.com`, `web.app`, `firebaseapp.com`, `glitch.me`, `onrender.com`, `workers.dev`, plus `sites.google.com`, `drive.google.com`, `docs.google.com`, `storage.googleapis.com`) are isolated via `is_hosted_user_content_subdomain()` and classified as `label = 2` (`legitimate_third_party_platform`), never auto-trusted.
- **No Synthetic Phishing Domains Mixed Into Training:** Lookalike test samples (`data/synthetic_lookalikes.csv`) strictly use reserved `.example` TLDs and are evaluated ONLY by test/benchmark scripts.

---

## 2. Multiclass & Binary Label Taxonomy (`src/seed_catalog.py`)

Binary URL and DOM classifiers train strictly on `binary_label in {0, 1}` derived from clean `multiclass_label in {0, 1, 2}` rows:

| Multiclass Label | Semantic Name | Binary Mapping | Total in `multiclass_dataset.csv` | Usage |
| ---: | --- | --- | ---: | --- |
| `0` | `verified_phishing` | `0` (Phishing / Malicious) | `26,023` | URL & DOM classifier training/eval |
| `1` | `official_legitimate` | `1` (Benign / Legitimate) | `33,450` | URL & DOM classifier training/eval |
| `2` | `legitimate_third_party_platform` | `1` (Benign / Legitimate) | `59` | Non-hosting verified third-party platforms (`razorpay`, `stripe`, `paypal`, news/SaaS) |
| `3` | `suspicious_or_uncertain` | Quarantined (`-1`) | `517` | Unvetted Tranco / uncertain domains (`uncertain_samples.csv`) |
| `4` | `compromised_or_anomaly` | Isolated (`0` in `compromised_samples.csv`) | `7,298` | Phishing/malicious paths on shared hosts, anomalous/compromised records |

Total combined `data/processed/multiclass_dataset.csv` rows: **`67,347`**.

---

## 3. Data Catalog & Domain-Disjoint Splits

| Artifact Path | Purpose | Verified Rows | Unique Root Domains | Notes |
| --- | --- | ---: | ---: | --- |
| `data/verified_domains.csv` | Verified seed catalog across Categories A–G | `115` | `107` | Labels: `1` (`88`), `2` (`26`), `3` (`1` — `canarabank.in` unverified candidate); `0` null cells, `0` duplicate URLs |
| `data/phishing_domains.csv` | Real verified phishing URLs | `3,800` | `3,561` | OpenPhish cached/live + PhreshPhish parquet + verified discovery list (`0` duplicate URLs) |
| `data/synthetic_lookalikes.csv` | Synthetic brand impersonation QA fixture | `10` | `10` | Strictly reserved `.example` hosts for automated QA (`evaluate_false_positives.py`) |
| `data/processed/url_dataset.csv` | Clean binary URL training/eval corpus | `59,532` | `57,331` | `26,023` Phishing (`0`) / `33,509` Benign (`1`), `0` missing cells, `0` label conflicts |
| `data/processed/dom_dataset.csv` | Clean binary DOM training/eval corpus | `6,015` | `5,534` | `3,009` Phishing (`0`) / `3,006` Benign (`1`), `0` missing cells, `0` conflicts |
| `data/processed/uncertain_samples.csv` | Excluded unvetted Tranco candidates | `517` | `517` | Quarantined from binary ML training |
| `data/processed/operational_status_samples.csv` | Excluded firewall/unreachable fixtures | `2` | `2` | Isolated to prevent confusing offline/blocked states with malware |

### Source Distribution (`url_dataset.csv` / `combined_dataset.csv`)

- `phiusiil`: `53,480`
- `phreshphish`: `5,411`
- `verified_seed_legit`: `434` (realistic Category A–G inner/query/search URLs)
- `openphish`: `116`
- `tranco_vetted`: `74`
- `custom_verified_fixture`: `17`

### Domain-Disjoint Splits (`verify_domain_disjoint` = PASS / `0` root domain overlap)

- **URL Splits:** `url_train.csv` = **`38,709`** (`37,264` domains) | `url_val.csv` = **`8,931`** (`8,600` domains) | `url_test.csv` = **`11,892`** (`11,467` domains)
- **DOM Splits:** `dom_train.csv` = **`3,128`** (`2,937` domains) | `dom_val.csv` = **`730`** (`678` domains) | `dom_test.csv` = **`968`** (`904` domains) | `dom_temporal_test.csv` = **`1,080`**

---

## 4. Pipeline Scripts (`scripts/`)

1. `python scripts/update_trusted_domains.py` *(pass `--verify-live` for TLS reachability checks)* -> rebuilds `data/verified_domains.csv`
2. `python scripts/update_threat_feeds.py` *(pass `--fetch-live` for OpenPhish refresh)* -> rebuilds `data/phishing_domains.csv` & `data/synthetic_lookalikes.csv`
3. `python scripts/build_training_dataset.py` -> invokes `src/build_datasets.py` + `scripts/deduplicate_dataset.py` + `scripts/validate_dataset.py`
4. `python scripts/validate_dataset.py` -> verifies schemas, null counts, duplicate URLs, multiclass distribution, and `verify_domain_disjoint` across all splits.

---

## 5. Privacy & Repository Safeguards

- `validate_dataset_schema()` rejects any dataframe containing `FORBIDDEN_CREDENTIAL_COLUMNS` (`password`, `passwd`, `cookie`, `cookies`, `token`, `auth_token`, `secret`).
- `.gitignore` excludes `data/raw/`, `data/processed/`, `data/feedback/`, and large `.csv`/`.json.gz` datasets while allowing lightweight reproducible catalogs (`verified_domains.csv`, `synthetic_lookalikes.csv`, `phishing_domains.csv` or local rebuilds).
