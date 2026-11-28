# WebShield AI v3.0 — Dataset Quality & Validation Report

**Generated At:** `2026-11-28T14:26:30.776990+00:00`

---

## 1. Corpus Overview & Partition Separation

| Dataset File | Verified Rows | Unique Root Domains | Phishing / Malicious (`0`) | Benign (`1`) | Non-Binary (`-1`) | Null Cells |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `data/processed/url_dataset.csv` | 59,532 | 57,331 | 26,023 | 33,509 | 0 | 0 |
| `data/processed/dom_dataset.csv` | 6,015 | 5,534 | 3,009 | 3,006 | 0 | 0 |
| `data/processed/uncertain_samples.csv` | 517 | 517 | 0 | 0 | 517 | 0 |
| `data/processed/operational_status_samples.csv` | 2 | 2 | 0 | 0 | 2 | 0 |

### Domain-Disjoint Splits (`verify_domain_disjoint` = PASS / 0 Overlap)
- **URL Splits:** Train `38,709` (`37,264` domains) | Val `8,931` (`8,600` domains) | Test `11,892` (`11,467` domains)
- **DOM Splits:** Train `3,128` (`2,937` domains) | Val `730` (`678` domains) | Test `968` (`904` domains)

---

## 2. Duplicate, Conflict & Timestamp Checks

- **Exact Duplicate URLs Removed Across Union:** `71`
- **Conflicting Binary Labels Resolved Across Multi-Source Merge:** `0` (verified malicious signals prioritized over unverified/stale labels)
- **Near-Duplicate Path-Normalized URLs Observed:** URL corpus `254` | DOM corpus `11`
- **Timestamp Coverage (`date` column):** `2024-01-01` to `2026-11-28` (invalid/missing dates: `0`)

---

## 3. Source Distribution (`combined_dataset.csv`)

| Source | Verified Count |
| --- | ---: |
| `phiusiil` | 53,480 |
| `phreshphish` | 5,411 |
| `verified_seed_legit` | 434 |
| `openphish` | 116 |
| `tranco_vetted` | 74 |
| `custom_verified_fixture` | 17 |

---

## 4. 18-Category Threat Taxonomy Distribution

| Taxonomy Category | Verified Count |
| --- | ---: |
| `https_legitimate` | 33,479 |
| `http_phishing` | 15,151 |
| `https_phishing` | 9,241 |
| `fake_login` | 1,353 |
| `fake_banking` | 271 |
| `http_legitimate` | 30 |
| `fake_ecommerce` | 1 |
| `fake_payment` | 1 |
| `homoglyph` | 1 |
| `punycode` | 1 |
| `ip_based_phishing` | 1 |
| `typosquatting` | 1 |
| `url_shortener` | 1 |

---

## 5. Numeric Feature Distribution & Extreme Outlier Audit (`> Q3 + 3*IQR`)

### URL Features (Top Variance / Outliers)
| Feature | Mean | Median | Max | Outliers (`> 3xIQR`) |
| --- | ---: | ---: | ---: | ---: |
| `num_special_chars` | 4.9247 | 4.0 | 635.0 | 3,223 |
| `url_length` | 32.764 | 25.0 | 4032.0 | 3,137 |
| `domain_length` | 17.8641 | 16.0 | 100.0 | 1,607 |
| `char_continuation_rate` | 0.0957 | 0.0909 | 0.5873 | 233 |
| `tld_length` | 2.7633 | 3.0 | 11.0 | 180 |
| `num_dots` | 1.423 | 1.0 | 84.0 | 177 |
| `url_entropy` | 3.8735 | 3.8454 | 5.9588 | 105 |
| `special_char_ratio` | 0.1674 | 0.1667 | 0.625 | 3 |
| `path_length` | 5.2764 | 1.0 | 3997.0 | 0 |
| `query_length` | 1.8488 | 0.0 | 2481.0 | 0 |

### DOM Features (Top Variance / Outliers)
| Feature | Mean | Median | Max | Outliers (`> 3xIQR`) |
| --- | ---: | ---: | ---: | ---: |
| `suspicious_link_ratio` | 0.0922 | 0.0 | 1.0 | 1,122 |
| `external_link_ratio` | 0.1493 | 0.0 | 1.0 | 941 |
| `dynamic_dom_mutation_count` | 0.7318 | 0.0 | 20.0 | 209 |
| `num_external_scripts` | 6.8306 | 2.0 | 228.0 | 143 |
| `inline_script_count` | 4.324 | 2.0 | 58.0 | 141 |
| `total_forms` | 0.6007 | 0.0 | 53.0 | 101 |
| `html_line_count` | 440.2042 | 239.0 | 19902.0 | 99 |
| `num_password_fields` | 0.7746 | 0.0 | 90.0 | 0 |
| `num_username_email_inputs` | 0.2181 | 0.0 | 11.0 | 0 |
| `num_login_forms` | 0.2931 | 0.0 | 13.0 | 0 |
