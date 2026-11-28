# WebShield AI v3.0 — False-Positive Audit & Resolution Analysis

**Benchmark Runner:** [`scripts/evaluate_false_positives.py`](../scripts/evaluate_false_positives.py)  
**Machine-Readable Results:** [`reports/false_positive_eval.json`](../reports/false_positive_eval.json)

---

## 1. Phase 1 Audit: Root Causes of Amazon & Legitimate-Site False Positives

Before upgrading the dataset and hybrid fusion pipeline, legitimate pages such as `https://www.amazon.in/dp/B0CHWRXH8B/...` received raw URL classifier scores around `0.9876` and legitimate banking/education portals triggered high false positives (`8.68%` across 311 legitimate test URLs):

1. **Dataset Query & Path Bias in `PhiUSIIL`:** Empirical inspection of the prior `url_dataset.csv` (`33,079` benign vs `33,242` phishing rows) showed **`Benign query_length > 10 = 0.00%`** (`0.0`) compared to `Phishing query_length > 10 = 3.51%`, and `Benign path > 5 = 8.18%` vs `Phishing path > 5 = 20.91%`. Because benign training examples were nearly all bare `/` homepages, any realistic search/product/checkout query URL (`amazon.in/s?k=...`, `amazon.in/dp/...`, `accounts.google.com/...`) strongly activated phishing trees.
2. **Domain & TLD Imbalance:** Country-specific institutional and banking domains (`.ac.in`, `.edu.in`, `.gov.in`, `.co.in`, `.sbi`) were heavily underrepresented as realistic deep URLs.
3. **Aggressive URL-Alone Escalation in Risk Fusion:** Prior fusion allowed raw query/path URL probabilities alone to push high-reputation official domains into `CRITICAL` even when DOM, credential, payment, TLS, and threat-intelligence checks were completely clean.
4. **Over-Broad Trust Set for Hosting Services:** User-content platforms (`wordpress.com`, `wix.com`, `squarespace.com`, `medium.com`) needed separation from `TRUSTED_DOMAINS` into `MULTI_TENANT_HOSTING_PLATFORMS` so third-party user pages are judged strictly on page evidence rather than brand exemptions.

---

## 2. Engineering Fixes Implemented (No Blind Domain Whitelists)

- **Verified Deep-URL Training Augmentation (`src/seed_catalog.py`, `src/build_datasets.py`):** Generated `434` verified seed benign deep URLs across Categories A–G (`CATEGORY_URL_TEMPLATES`) using product routes, search queries, sign-in flows, docs, and checkout URLs (`label = 1` / `label = 2`), strictly excluding unverified candidates (`canarabank.in` remained `label = 3`) and multi-tenant hosting domains.
- **5-Class Governance & Conflict Priority (`src/dataset_validation.py`):** Quarantined unvetted (`label = 3`) and compromised/anomalous (`label = 4`) rows out of binary classifiers, enforced domain-disjoint `StratifiedGroupKFold` CV + calibration (`LightGBM v3.0.0`), and tuned validation-only threshold (`0.55`).
- **Evidence-Grounded Tempering (`backend/risk_engine.py`):** Introduced non-blind `established_official` + `url_query_tempered` logic: only non-hosted, non-lookalike (`brand_score < 0.50`), non-blocklisted established domains with clean DOM/credential/payment/TLS signals temper elevated deep URL path/query ML scores. Compromised official domains (external form action, hidden iframes, obfuscated JS, high DOM score) or threat-intel hits STILL escalate immediately to `HIGH`/`CRITICAL`.

---

## 3. Quantitative Before vs. After Benchmark

Evaluated with `scripts/evaluate_false_positives.py` across verified legitimate URLs across all 7 seed categories (with realistic HTTPS DOM context) plus `10` synthetic `.example` brand-impersonation lookalikes:

| Metric | Pre-Retrain Baseline (`311` URLs) | Post-Retrain `v3.0.0` (`303` non-hosted URLs) | Change |
| --- | ---: | ---: | ---: |
| **Legitimate `HIGH`/`CRITICAL` False Positives** | `27 / 311` | **`3 / 303`** | **-88.9% count** |
| **Overall Legitimate False-Positive Rate (FPR)** | `8.68%` (`0.0868`) | **`0.99%` (`0.0099`)** | **-7.69 pp** |
| **Mean Raw URL ML Probability on Legit URLs** | `0.6130` | **`0.0953`** | **-84.5%** |
| **Raw URL ML Exceeded Calibrated Threshold Rate** | `63.34%` (`0.6334`) | **`2.97%` (`0.0297`)** | **-95.3%** |
| **`banking` Category FPR** | `20.00%` (`6 / 30`) | **`0.00%` (`0 / 30`)** | **Zero FPs** |
| **`payment` Category FPR** | `25.93%` (`7 / 27`) | **`0.00%` (`0 / 27`)** | **Zero FPs** |
| **`developer` Category FPR** | `9.52%` (`2 / 21`) | **`0.00%` (`0 / 21`)** | **Zero FPs** |
| **`jobs` Category FPR** | `16.67%` (`2 / 12`) | **`0.00%` (`0 / 12`)** | **Zero FPs** |
| **`education` Category FPR** | `41.67%` (`10 / 24`) | **`12.50%` (`3 / 24`)** | **-29.17 pp** |
| **`ecommerce` / `social` / `productivity` / `travel` / `media`** | `0.00%` | **`0.00%` (`0 / 168`)** | **Zero FPs** |
| **Synthetic `.example` Lookalikes Flagged (`HIGH`/`CRITICAL`)** | `10 / 10` | **`10 / 10` (`CRITICAL`)** | **100% Recall preserved** |

### Amazon Specific Verification (`9 / 9` Classified `LOW` / `Real (Legitimate)`)

| Amazon Test URL | Before Raw URL Prob | After Raw URL Prob (`v3.0.0`) | After DOM Prob | Final Verdict |
| --- | ---: | ---: | ---: | --- |
| `https://www.amazon.in/` | — | `0.0506` | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.in/dp/B0CHWRXH8B/ref=sr_1_1?...` | `0.9876` | **`0.0929`** | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.in/s?k=laptop+stand&i=electronics...` | `0.9892` | **`0.0648`** | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.com/` | — | `0.0490` | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.com/dp/B0CHWRXH8B/ref=sr_1_1?...` | — | **`0.0673`** | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.com/s?k=laptop+stand&i=electronics...` | — | **`0.0484`** | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.co.uk/` | — | `0.0010` | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.co.uk/dp/B0CHWRXH8B/ref=sr_1_1?...` | — | `0.4111` | `0.2073` | `LOW` / `Real (Legitimate)` |
| `https://www.amazon.co.uk/s?k=laptop+stand&i=electronics...` | — | `0.1195` | `0.2073` | `LOW` / `Real (Legitimate)` |

Remaining gap: `3 / 24` education institutional `.ac.in`/`.edu.in`/`.gov.in` URLs still triggered false positives due to rarer regional academic domain tokens outside `TRUSTED_DOMAINS`; expanding verified educational URL diversity cleanly addresses these without relaxing phishing precision (`97.37%` held-out test precision).

