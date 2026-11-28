# WebShield AI v3.0 — Model Evaluation & Registry Report

**Active Registry Manifest:** [`models/registry/active_manifest.json`](../models/registry/active_manifest.json)  
**Class Mapping Convention:** `0 = Phishing / Malicious` (positive target) | `1 = Benign / Legitimate`

---

## 1. Anti-Leakage & Calibration Protocol

1. Raw URL and DOM corpora are strictly partitioned by PSL registrable `root_domain` (`verify_domain_disjoint` = `0` domain overlap across `train`, `val`, `test`, and chronological `dom_temporal_test.csv` reserved first).
2. Candidate models are compared using training-only `StratifiedGroupKFold` cross-validation and held-out **Validation** metrics ONLY. Test splits are never inspected during model selection or hyperparameter adjustment.
3. Probabilities are calibrated strictly inside the training partition using explicit domain-grouped `StratifiedGroupKFold` splits passed to `CalibratedClassifierCV` (`sigmoid` `cv=3` for URL, `isotonic` `cv=5` for DOM).
4. Phishing classification operating thresholds (`0.44` for URL, `0.65` for DOM) are tuned strictly on validation probabilities (`optimize_phishing_threshold`, `pos_label=0`).
5. Promotion gates (`Phishing F1 >= 0.85`, `ROC AUC >= 0.90`, `FPR <= 0.08`) are evaluated strictly on **validation metrics** prior to atomic promotion (`os.replace()`); held-out test metrics and read-only `test_audit_notes` are logged post-promotion without leaking into promotion decisions.

---

## 2. Model 1 — URL Risk Classifier (`url_risk`, v3.0.0)

### A. Validation-Only Candidate Comparison (`url_val.csv`, `n = 9,954`, threshold = `0.50`)

Source: [`reports/url_validation_comparison.csv`](url_validation_comparison.csv)

| Candidate Model | CV Phishing F1 | Val Accuracy | Val Phishing Prec (0) | Val Phishing Rec (0) | Val Phishing F1 (0) | Val Benign F1 (1) | Val ROC AUC | Val PR AUC | Val FPR | Val FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **XGBoost (Winner)** | 0.9655 | 0.9663 | 0.9737 | 0.9606 | 0.9671 | 0.9655 | 0.9905 | 0.9926 | 0.0276 | 0.0394 | 23.300 |
| **LightGBM** | 0.9663 | 0.9662 | 0.9773 | 0.9567 | 0.9669 | 0.9656 | 0.9902 | 0.9926 | 0.0236 | 0.0433 | 37.033 |
| **HistGradientBoosting** | 0.9650 | 0.9662 | 0.9775 | 0.9565 | 0.9669 | 0.9656 | 0.9900 | 0.9923 | 0.0234 | 0.0435 | 39.354 |
| **Random Forest** | 0.9602 | 0.9596 | 0.9650 | 0.9563 | 0.9606 | 0.9585 | 0.9886 | 0.9912 | 0.0369 | 0.0437 | 26.226 |
| **Logistic Regression** | 0.9430 | 0.9414 | 0.9624 | 0.9224 | 0.9420 | 0.9409 | 0.9742 | 0.9807 | 0.0384 | 0.0776 | 22.861 |

### B. Promoted Final URL Winner Evaluation (`XGBoost`, threshold = `0.44`)

Source: [`reports/model_comparison_results.csv`](model_comparison_results.csv) & [`models/registry/active_manifest.json`](../models/registry/active_manifest.json)

| Partition | Samples | Accuracy | Phishing Prec (0) | Phishing Rec (0) | Phishing F1 (0) | Benign F1 (1) | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Validation (`url_val`)** | 9,954 | 0.9671 | 0.9728 | 0.9632 | 0.9680 | 0.9663 | 0.9905 | 0.9926 | 0.0286 | 0.0368 |
| **Untouched Held-Out Test (`url_test`)** | 13,288 | **0.9662** | **0.9739** | **0.9586** | **0.9662** | **0.9662** | **0.9901** | **0.9926** | **0.0261** | **0.0414** |

- **Held-Out Test Confusion Matrix:** `TP (Phishing=0) = 6,412` | `FN = 277` | `FP = 172` | `TN (Benign=1) = 6,427`
- **Promotion Gate Result:** `PROMOTED` (`v3.0.0`, full SHA-256 verified across model, feature schema & encoder) | `Test audit passed.`

---

## 3. Model 2 — DOM Behaviour Classifier (`dom_behavior`, v3.0.0)

### A. Validation-Only Candidate Comparison (`dom_val.csv`, `n = 730`, threshold = `0.50`)

Source: [`reports/dom_validation_comparison.csv`](dom_validation_comparison.csv)

| Candidate Model | CV Phishing F1 | Val Accuracy | Val Phishing Prec (0) | Val Phishing Rec (0) | Val Phishing F1 (0) | Val Benign F1 (1) | Val ROC AUC | Val PR AUC | Val FPR | Val FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **DOM XGBoost (Winner)** | 0.8926 | 0.8986 | 0.9144 | 0.9007 | 0.9075 | 0.8879 | 0.9536 | 0.9659 | 0.1040 | 0.0993 | 4.167 |
| **DOM Random Forest** | 0.8958 | 0.8959 | 0.9098 | 0.9007 | 0.9052 | 0.8845 | 0.9579 | 0.9706 | 0.1101 | 0.0993 | 6.919 |
| **DOM LightGBM** | 0.8981 | 0.8877 | 0.9147 | 0.8784 | 0.8962 | 0.8776 | 0.9545 | 0.9670 | 0.1009 | 0.1216 | 6.693 |
| **DOM GradientBoosting** | 0.8839 | 0.8863 | 0.9103 | 0.8809 | 0.8953 | 0.8756 | 0.9447 | 0.9565 | 0.1070 | 0.1191 | 6.362 |
| **DOM Extra Trees** | 0.8835 | 0.8781 | 0.9046 | 0.8710 | 0.8875 | 0.8670 | 0.9475 | 0.9605 | 0.1131 | 0.1290 | 5.867 |

### B. Promoted Final DOM Winner Evaluation (`DOM XGBoost`, threshold = `0.65`)

Source: [`reports/dom_model_comparison.csv`](dom_model_comparison.csv) & [`models/registry/active_manifest.json`](../models/registry/active_manifest.json)

| Partition | Samples | Accuracy | Phishing Prec (0) | Phishing Rec (0) | Phishing F1 (0) | Benign F1 (1) | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Validation (`dom_val`)** | 730 | 0.8836 | 0.9392 | 0.8437 | 0.8889 | 0.8777 | 0.9536 | 0.9659 | 0.0673 | 0.1563 |
| **Untouched Held-Out Test (`dom_test`)** | 968 | **0.8729** | **0.9112** | **0.8418** | **0.8751** | **0.8707** | **0.9412** | **0.9422** | **0.0921** | **0.1582** |
| **Domain-Disjoint Temporal (`dom_temporal_test`)** | 1,080 | 0.7565 | 0.8029 | 0.5185 | 0.6301 | 0.8185 | 0.8481 | 0.8024 | 0.0849 | 0.4815 |

- **Held-Out Test Confusion Matrix:** `TP (Phishing=0) = 431` | `FN = 81` | `FP = 42` | `TN (Benign=1) = 414`
- **Promotion Gate Result:** `PROMOTED` (`v3.0.0`, full SHA-256 verified) | Read-only audit note: `Test audit note: FPR 0.0921 > 0.08` (validation FPR was `0.0673 <= 0.08`; strictly domain-disjoint temporal evaluation highlights genuine distribution drift over newer domains).
