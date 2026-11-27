# Dataset Engineering & Feature Schema Documentation

## 1. Multi-Source Data Philosophy

Rather than relying solely on synthetic augmentation or a single static URL file, the upgraded pipeline in [`src/build_datasets.py`](../src/build_datasets.py) separates raw telemetry by modality (pure URL vs. pure DOM behaviour), preserves source provenance, isolates unverified candidates, and enforces domain-grouped splitting so pages from the same root domain cannot leak across train, validation, and test partitions.

### Integrated Sources

| Source | Role & License / Access | Contribution (Verified Build) | Notes |
| --- | --- | --- | --- |
| **PhiUSIIL Phishing URL Dataset** (`dataset/PhiUSIIL_Phishing_URL_Dataset.csv`) | Baseline URL & domain ground truth | **59,919** rows (capped at 2 per `root_domain`) | Prior synthetic rows matching `SYNTHETIC_PREFIXES` (`valid-site-*`, `scam-shop-*`, etc.) are stripped before URL feature extraction. |
| **PhreshPhish** (`phreshphish/phreshphish`, Hugging Face CC-BY-4.0) | Real benign & phishing HTML + URLs + dates + brand targets | **806** unique domain-capped rows (from 997 cached HTML samples; max 3 per `root_domain`) | Cached safely in `data/raw/phreshphish_sample.json.gz`. HTML is parsed statically with BeautifulSoup (JavaScript is never executed). |
| **OpenPhish** (`https://openphish.com/feed.txt`) | Live phishing threat intelligence feed | **300** active verified phishing URLs | Respects request timeouts; gracefully logs if offline. |
| **Tranco Top-1M** (`dataset/tranco_top1m.json.gz`) | Popularity candidate index | **72** vetted trusted rows (`tranco_vetted`) | Top candidates *not* in `TRUSTED_DOMAINS` are **not** assumed safe; **417** unvetted candidates are quarantined in `data/processed/uncertain_samples.csv`. |
| **Custom Verified & Static Fixtures** (`data/external/custom_verified.csv`) | Verified consumer-fraud registry & offline multi-label HTML fixtures | **8** rows (`7` static HTML fixtures + `1` registry entry) | Covers benign HTTP pages, legitimate portals, credential harvesting, brand impersonation, fake e-commerce upfront-payment traps, deceptive redirects, and fake download buttons. |
| **URLhaus & PhishTank** (Optional Adapters) | Malware distribution & crowdsourced phishing feeds | Optional (`0` when keys unset) | Requires `URLHAUS_AUTH_KEY` (v2 export) or `PHISHTANK_API_KEY`; skips gracefully on missing keys, HTTP 410, or rate limits. |

---

## 2. Multi-Label Risk Taxonomy & Provenance Schema

Every record in [`data/processed/combined_dataset.csv`](../data/processed/combined_dataset.csv) and [`data/processed/uncertain_samples.csv`](../data/processed/uncertain_samples.csv) preserves 13 metadata & provenance columns defined alongside `RISK_CATEGORIES` in [`src/dataset_validation.py`](../src/dataset_validation.py):

- **Allowed `RISK_CATEGORIES`**: `benign`, `phishing`, `brand_impersonation`, `malware_distribution`, `credential_risk`, `payment_risk`, `deceptive_behavior`, `suspicious_redirect`, `unknown`.
- **Columns (`combined_dataset.csv` & `uncertain_samples.csv`)**: `url`, `domain`, `root_domain`, `source`, `collection_timestamp`, `verification_status`, `html_available`, `primary_label`, `risk_labels`, `binary_label` (`1` = benign, `0` = threat/unsafe, `-1` = uncertain), `confidence`, `evidence`, `date`.

User-submitted feedback from `POST /feedback` is appended to `data/feedback/reports.jsonl` with `"verification_status": "pending_human_review"` and is **never** automatically promoted into training datasets without manual review.

---

## 3. Processed Datasets & Domain-Disjoint Splits

| File | Rows | Columns | Unique Root Domains | Label Breakdown | Split Strategy |
| --- | ---: | ---: | ---: | --- | --- |
| `data/processed/combined_dataset.csv` | 61,105 | 13 | 58,401 | 30,623 benign (`1`), 30,482 unsafe (`0`) | Deduplicated verified union (`phishing`: 30,478, `payment_risk`: 2, `malware_distribution`: 1, `suspicious_redirect`: 1) |
| `data/processed/url_dataset.csv` | 61,105 | 35 | 58,401 | 30,623 benign (`1`), 30,482 unsafe (`0`) | Pure URL features (`URL_FEATURE_COLUMNS`, 27 cols) + 8 metadata/label cols |
| `data/processed/url_train.csv` | 42,668 | 35 | 40,880 | 21,443 benign, 21,225 unsafe | `GroupShuffleSplit` on `root_domain` |
| `data/processed/url_val.csv` | 6,129 | 35 | 5,840 | 3,019 benign, 3,110 unsafe | Disjoint `root_domain` validation set |
| `data/processed/url_test.csv` | 12,308 | 35 | 11,681 | 6,161 benign, 6,147 unsafe | Disjoint `root_domain` held-out test set |
| `data/processed/dom_dataset.csv` | 813 | 47 | 710 | 551 benign (`1`), 262 unsafe (`0`) | 36 `DOM_FEATURE_COLUMNS` + 3 `DOM_OBSERVABILITY_COLUMNS` + 8 metadata cols |
| `data/processed/dom_train.csv` | 572 | 47 | 497 | 391 benign, 181 unsafe | `GroupShuffleSplit` on `root_domain` |
| `data/processed/dom_val.csv` | 82 | 47 | 71 | 56 benign, 26 unsafe | Disjoint `root_domain` validation set |
| `data/processed/dom_test.csv` | 159 | 47 | 142 | 104 benign, 55 unsafe | Disjoint `root_domain` held-out test set |
| `data/processed/dom_temporal_test.csv` | 202 | 47 | 190 | 151 benign, 51 unsafe | Chronological newest 25% of PhreshPhish records (`temporal_train_test_split`) |
| `data/processed/uncertain_samples.csv` | 417 | 13 | 417 | 417 unknown (`-1`) | Quarantined unvetted Tranco candidates |

Zero-overlap leakage checks (`verify_domain_disjoint`) confirm that `40,880 + 5,840 + 11,681 = 58,401` (`url_*`) and `497 + 71 + 142 = 710` (`dom_*`) have **0 overlapping root domains** across train/val/test partitions.

---

## 4. Separated Feature Schemas

### A. URL Classifier Features (`URL_FEATURE_COLUMNS`, 27 columns — `src/features.py`)

`url_length`, `domain_length`, `path_length`, `query_length`, `num_subdomains`, `num_dots`, `num_hyphens_domain`, `num_digits_url`, `num_digits_domain`, `num_special_chars`, `is_ip_address`, `is_punycode_or_idn`, `has_unusual_port`, `is_url_shortener`, `has_url_obfuscation`, `url_entropy`, `domain_entropy`, `tld_length`, `is_suspicious_tld`, `suspicious_keyword_count`, `is_https`, `brand_similarity_score`, `typosquat_edit_distance`, `char_continuation_rate`, `letter_ratio`, `digit_ratio`, `tld`.

### B. DOM Behaviour Classifier Features (`DOM_FEATURE_COLUMNS`, 36 columns — `src/dom_features.py`)

- **Group A — Login & Credential Features (8)**: `num_password_fields`, `num_username_email_inputs`, `num_login_forms`, `has_external_form_action`, `num_cross_domain_forms`, `num_hidden_credential_inputs`, `suspicious_login_indicators`, `brand_domain_mismatch`.
- **Group B — Form & Payment Features (8)**: `total_forms`, `external_forms_count`, `has_post_form`, `num_sensitive_inputs`, `num_payment_inputs`, `has_suspicious_payment_dest`, `has_prepaid_without_cod`, `has_restrictive_refund_terms`.
- **Group C — Advertisement, Redirect & Deceptive Behaviour (11)**: `num_iframes`, `num_hidden_iframes`, `num_external_scripts`, `popup_trigger_count`, `fake_download_button_count`, `suspicious_link_ratio`, `meta_refresh_redirects`, `js_redirect_indicators`, `misleading_button_count`, `external_link_ratio`, `notification_prompt_requested`.
- **Group D — JavaScript & Webpage Architecture (9)**: `inline_script_count`, `suspicious_inline_js_count`, `obfuscated_js_score`, `dynamic_dom_mutation_count`, `html_line_count`, `has_title`, `domain_title_match_score`, `has_copyright_notice`, `has_official_contact_cue`.
- **Observability Metadata (`DOM_OBSERVABILITY_COLUMNS`, excluded from classifier input vectors)**: `is_https`, `mixed_content_count`, `cross_origin_iframes_uninspected`.

---

## 5. Gitignore & Privacy Safeguards

- `validate_dataset_schema()` raises an error if any column matches `FORBIDDEN_CREDENTIAL_COLUMNS` (`password`, `passwd`, `cookie`, `cookies`, `token`, `auth_token`, `secret`).
- `.gitignore` excludes `data/raw/`, `data/processed/`, `data/feedback/`, `dataset/*.csv`, and `dataset/*.json.gz` so large raw scrapes, secrets, and user feedback queues are never committed to GitHub.

