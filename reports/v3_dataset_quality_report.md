# WebShield AI v3.0 — Dataset Quality & Validation Report

**Generated At:** `2026-11-28T07:51:31.105824+00:00`

---

## 1. Corpus Overview & Partition Separation

| Dataset File | Verified Rows | Unique Root Domains | Phishing / Malicious (`0`) | Benign (`1`) | Non-Binary (`-1`) | Null Cells |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `data/processed/url_dataset.csv` | 66,321 | 64,359 | 33,242 | 33,079 | 0 | 0 |
| `data/processed/dom_dataset.csv` | 6,015 | 5,520 | 3,009 | 3,006 | 0 | 0 |
| `data/processed/uncertain_samples.csv` | 520 | 520 | 0 | 0 | 520 | 0 |
| `data/processed/operational_status_samples.csv` | 2 | 2 | 0 | 0 | 2 | 0 |

### Domain-Disjoint Splits (`verify_domain_disjoint` = PASS / 0 Overlap)
- **URL Splits:** Train `43,126` (`41,833` domains) | Val `9,948` (`9,654` domains) | Test `13,247` (`12,872` domains)
- **DOM Splits:** Train `3,913` (`3,588` domains) | Val `893` (`828` domains) | Test `1,209` (`1,104` domains)

---

## 2. Duplicate, Conflict & Timestamp Checks

- **Exact Duplicate URLs Removed Across Union:** `76`
- **Conflicting Binary Labels Resolved Across Multi-Source Merge:** `0` (verified malicious signals prioritized over unverified/stale labels)
- **Near-Duplicate Path-Normalized URLs Observed:** URL corpus `292` | DOM corpus `11`
- **Timestamp Coverage (`date` column):** `2024-01-01` to `2026-11-28` (invalid/missing dates: `0`)

---

## 3. Source Distribution (`combined_dataset.csv`)

| Source | Verified Count |
| --- | ---: |
| `phiusiil` | 59,930 |
| `phreshphish` | 5,995 |
| `openphish` | 300 |
| `tranco_vetted` | 78 |
| `custom_verified_fixture` | 18 |

---

## 4. 18-Category Threat Taxonomy Distribution

| Taxonomy Category | Verified Count |
| --- | ---: |
| `https_legitimate` | 33,049 |
| `http_phishing` | 15,726 |
| `https_phishing` | 15,514 |
| `fake_login` | 1,628 |
| `fake_banking` | 366 |
| `http_legitimate` | 30 |
| `fake_ecommerce` | 1 |
| `fake_payment` | 1 |
| `homoglyph` | 1 |
| `punycode` | 1 |
| `compromised_legitimate` | 1 |
| `ip_based_phishing` | 1 |
| `typosquatting` | 1 |
| `url_shortener` | 1 |

---

## 5. Numeric Feature Distribution & Extreme Outlier Audit (`> Q3 + 3*IQR`)

### URL Features (Top Variance / Outliers)
| Feature | Mean | Median | Max | Outliers (`> 3xIQR`) |
| --- | ---: | ---: | ---: | ---: |
| `num_special_chars` | 4.9476 | 4.0 | 635.0 | 3,328 |
| `url_length` | 33.514 | 27.0 | 4032.0 | 2,526 |
| `domain_length` | 19.1337 | 17.0 | 100.0 | 804 |
| `char_continuation_rate` | 0.0959 | 0.0909 | 0.6087 | 261 |
| `num_dots` | 1.5003 | 1.0 | 84.0 | 185 |
| `tld_length` | 2.7805 | 3.0 | 11.0 | 181 |
| `url_entropy` | 3.9056 | 3.8797 | 5.9588 | 47 |
| `special_char_ratio` | 0.164 | 0.16 | 0.625 | 8 |
| `path_length` | 5.0044 | 1.0 | 3997.0 | 0 |
| `query_length` | 1.5863 | 0.0 | 2481.0 | 0 |

### DOM Features (Top Variance / Outliers)
| Feature | Mean | Median | Max | Outliers (`> 3xIQR`) |
| --- | ---: | ---: | ---: | ---: |
| `suspicious_link_ratio` | 0.0922 | 0.0 | 1.0 | 1,122 |
| `external_link_ratio` | 0.1491 | 0.0 | 1.0 | 941 |
| `dynamic_dom_mutation_count` | 0.7318 | 0.0 | 20.0 | 209 |
| `num_external_scripts` | 6.8303 | 2.0 | 228.0 | 143 |
| `inline_script_count` | 4.324 | 2.0 | 58.0 | 141 |
| `total_forms` | 0.6007 | 0.0 | 53.0 | 101 |
| `html_line_count` | 440.2042 | 239.0 | 19902.0 | 99 |
| `num_password_fields` | 0.7746 | 0.0 | 90.0 | 0 |
| `num_username_email_inputs` | 0.2181 | 0.0 | 11.0 | 0 |
| `num_login_forms` | 0.2931 | 0.0 | 13.0 | 0 |
