# WebShield AI v3.0 — Model Evaluation & Registry Report

**Active Registry Manifest:** [`models/registry/active_manifest.json`](../models/registry/active_manifest.json)  
**Class Mapping Convention:** `0 = Phishing / Malicious` (positive target) | `1 = Benign / Legitimate`

---

## 1. Anti-Leakage & Calibration Protocol

1. Raw URL and DOM corpora are strictly partitioned by PSL registrable `root_domain` (`verify_domain_disjoint` = `0` domain overlap across `train`, `val`, and `test`).
2. Candidate models are compared using training-only `StratifiedGroupKFold` cross-validation and held-out **Validation** metrics ONLY. Test splits are never inspected during model selection or hyperparameter adjustment.
3. Probabilities are calibrated strictly inside the training partition (`CalibratedClassifierCV`: `sigmoid` `cv=3` for URL, `isotonic` `cv=5` for DOM).
4. Phishing classification operating thresholds (`0.60` for URL, `0.67` for DOM) are tuned strictly on validation probabilities (`optimize_phishing_threshold`, `pos_label=0`).
5. Each promoted model is evaluated **once** on its untouched domain-disjoint test split (and chronological temporal split for DOM) and promoted atomically via `os.replace()` only when all security gates pass (`Phishing F1 >= 0.85`, `ROC AUC >= 0.90`, `FPR <= 0.08`).

---

## 2. Model 1 — URL Risk Classifier (`url_risk`, v3.0.0)

### A. Validation-Only Candidate Comparison (`url_val.csv`, `n = 9,948`, threshold = `0.50`)

Source: [`reports/url_validation_comparison.csv`](url_validation_comparison.csv)

| Candidate Model | CV Phishing F1 | Val Accuracy | Val Phishing Prec (0) | Val Phishing Rec (0) | Val Phishing F1 (0) | Val Benign F1 (1) | Val ROC AUC | Val PR AUC | Val FPR | Val FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **LightGBM (Winner)** | 0.9664 | 0.9659 | 0.9714 | 0.9608 | 0.9661 | 0.9658 | 0.9890 | 0.9910 | 0.0288 | 0.0392 | 38.787 |
| **XGBoost** | 0.9665 | 0.9652 | 0.9710 | 0.9598 | 0.9653 | 0.9651 | 0.9892 | 0.9916 | 0.0292 | 0.0402 | 23.546 |
| **HistGradientBoosting** | 0.9659 | 0.9646 | 0.9679 | 0.9618 | 0.9648 | 0.9644 | 0.9887 | 0.9905 | 0.0325 | 0.0382 | 49.026 |
| **Random Forest** | 0.9609 | 0.9582 | 0.9566 | 0.9608 | 0.9587 | 0.9577 | 0.9865 | 0.9886 | 0.0444 | 0.0392 | 34.214 |
| **Logistic Regression** | 0.9415 | 0.9429 | 0.9582 | 0.9273 | 0.9425 | 0.9433 | 0.9736 | 0.9695 | 0.0412 | 0.0727 | 12.975 |

### B. Promoted Final URL Winner Evaluation (`LightGBM`, threshold = `0.60`)

Source: [`reports/model_comparison_results.csv`](model_comparison_results.csv) & `models/registry/active_manifest.json`

| Partition | Samples | Accuracy | Phishing Prec (0) | Phishing Rec (0) | Phishing F1 (0) | Benign F1 (1) | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Validation (`url_val`)** | 9,948 | 0.9668 | 0.9780 | 0.9558 | 0.9668 | 0.9669 | 0.9890 | 0.9910 | 0.0219 | 0.0442 |
| **Untouched Held-Out Test (`url_test`)** | 13,247 | **0.9675** | **0.9788** | **0.9557** | **0.9671** | **0.9679** | **0.9891** | **0.9909** | **0.0207** | **0.0443** |

- **Held-Out Test Confusion Matrix:** `TP (Phishing=0) = 6,328` | `FN = 293` | `FP = 137` | `TN (Benign=1) = 6,489`
- **Promotion Gate Result:** `PROMOTED` (`v3.0.0`, SHA-256 verified)

---

## 3. Model 2 — DOM Behaviour Classifier (`dom_behavior`, v3.0.0)

### A. Validation-Only Candidate Comparison (`dom_val.csv`, `n = 893`, threshold = `0.50`)

Source: [`reports/dom_validation_comparison.csv`](dom_validation_comparison.csv)

| Candidate Model | CV Phishing F1 | Val Accuracy | Val Phishing Prec (0) | Val Phishing Rec (0) | Val Phishing F1 (0) | Val Benign F1 (1) | Val ROC AUC | Val PR AUC | Val FPR | Val FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **DOM LightGBM (Winner)** | 0.8766 | 0.8791 | 0.8776 | 0.8776 | 0.8776 | 0.8805 | 0.9432 | 0.9452 | 0.1195 | 0.1224 | 6.365 |
| **DOM Random Forest** | 0.8730 | 0.8746 | 0.8664 | 0.8821 | 0.8742 | 0.8750 | 0.9432 | 0.9425 | 0.1327 | 0.1179 | 5.777 |
| **DOM XGBoost** | 0.8733 | 0.8735 | 0.8644 | 0.8821 | 0.8732 | 0.8737 | 0.9416 | 0.9417 | 0.1350 | 0.1179 | 3.856 |
| **DOM Extra Trees** | 0.8598 | 0.8679 | 0.8765 | 0.8526 | 0.8644 | 0.8712 | 0.9354 | 0.9366 | 0.1173 | 0.1474 | 4.417 |
| **DOM GradientBoosting** | 0.8607 | 0.8533 | 0.8399 | 0.8685 | 0.8540 | 0.8526 | 0.9317 | 0.9286 | 0.1615 | 0.1315 | 6.995 |

### B. Promoted Final DOM Winner Evaluation (`DOM LightGBM`, threshold = `0.67`)

Source: [`reports/dom_model_comparison.csv`](dom_model_comparison.csv) & `models/registry/active_manifest.json`

| Partition | Samples | Accuracy | Phishing Prec (0) | Phishing Rec (0) | Phishing F1 (0) | Benign F1 (1) | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Validation (`dom_val`)** | 893 | 0.8746 | 0.9165 | 0.8209 | 0.8660 | 0.8821 | 0.9432 | 0.9452 | 0.0730 | 0.1791 |
| **Untouched Held-Out Test (`dom_test`)** | 1,209 | **0.8685** | **0.9193** | **0.7983** | **0.8545** | **0.8800** | **0.9383** | **0.9418** | **0.0657** | **0.2017** |
| **Chronological Temporal (`dom_temporal_test`)** | 1,500 | 0.8860 | 0.9177 | 0.7198 | 0.8068 | 0.9191 | 0.9585 | 0.9300 | 0.0319 | 0.2802 |

- **Held-Out Test Confusion Matrix:** `TP (Phishing=0) = 467` | `FN = 118` | `FP = 41` | `TN (Benign=1) = 583`
- **Promotion Gate Result:** `PROMOTED` (`v3.0.0`, SHA-256 verified)

