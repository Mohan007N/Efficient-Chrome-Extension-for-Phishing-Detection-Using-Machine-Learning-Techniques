# WebShield AI v3.0 — Model Training, Calibration & Registry Pipeline

**Registry Manifest:** [`models/registry/active_manifest.json`](../models/registry/active_manifest.json)  
**Target Label Convention:** `0 = Phishing / Malicious` (Positive Class) | `1 = Benign / Legitimate`

---

## 1. Training Scripts & Leakage-Free Protocol

Both URL ([`src/train.py`](../src/train.py)) and DOM ([`src/train_dom.py`](../src/train_dom.py)) training pipelines are orchestrated via `python run_train.py`:

1. **PSL Domain-Grouped Splits:** Raw URL (`59,532`) and DOM (`6,015`) datasets are partitioned by PSL registrable `root_domain` (`GroupShuffleSplit`, `verify_domain_disjoint = True`, zero shared domains across `train`, `val`, `test`, and reserved `dom_temporal_test`). Unvetted Tranco (`uncertain_samples.csv`) and compromised/anomaly (`compromised_samples.csv`) rows are kept out of binary classifiers.
2. **Domain-Grouped CV + Calibration:** Inside the training split only, each candidate passes `StratifiedGroupKFold` grouped by `root_domain` (`cv=3` for URL, `cv=5` for DOM) into `CalibratedClassifierCV` (`method="sigmoid"` for URL, `method="isotonic"` for DOM) using explicit CV split iterators — preventing same-domain leakage during calibration.
3. **Validation-Only Model Selection & Threshold Tuning:** Candidates compete strictly on `url_val.csv` (`n = 8,931`) and `dom_val.csv` (`n = 730`). `optimize_phishing_threshold()` searches operating thresholds (`0.55` for URL, `0.65` for DOM) strictly on validation probabilities (`pos_label=0`).
4. **Validation-Only Registry Gates (`src/model_registry.py`):** Promotion requires passing `Phishing F1 >= 0.85`, `ROC AUC >= 0.90`, and `FPR <= 0.08` on validation metrics, followed by atomic `os.replace()` pointer updates and SHA-256 checksums for model `.pkl`, `*_feature_columns.pkl`, and encoders. Test metrics are evaluated and logged read-only post-promotion (`test_audit_notes`).
5. **Experiment Tracking:** Hyperparameters, grouped CV F1, validation/test metrics, and runtime are logged to MLflow (`sqlite:///mlruns/mlflow.db`).

---

## 2. Model 1 — URL Risk Classifier (`url_risk`, v3.0.0)

### Validation Candidate Comparison (`url_val.csv`, `n = 8,931`, threshold = `0.50`)

Source: [`reports/url_validation_comparison.csv`](../reports/url_validation_comparison.csv)

| Candidate Model | CV Phishing F1 | Val Accuracy | Val Phishing Prec | Val Phishing Rec | Val Phishing F1 | Val Benign F1 | Val ROC AUC | Val PR AUC | Val FPR | Val FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **LightGBM (Promoted `v3.0.0`)** | **0.9562** | **0.9619** | **0.9672** | 0.9469 | **0.9570** | **0.9659** | **0.9866** | **0.9883** | **0.0259** | 0.0531 | 58.08 |
| **XGBoost** | 0.9554 | 0.9608 | 0.9643 | **0.9474** | 0.9558 | 0.9648 | 0.9863 | 0.9880 | 0.0283 | **0.0526** | 40.95 |
| **HistGradientBoosting** | 0.9549 | 0.9605 | 0.9657 | 0.9451 | 0.9553 | 0.9646 | 0.9862 | 0.9880 | 0.0271 | 0.0549 | 72.80 |
| **Random Forest** | 0.9489 | 0.9536 | 0.9488 | **0.9474** | 0.9481 | 0.9581 | 0.9839 | 0.9860 | 0.0413 | **0.0526** | 46.33 |
| **Logistic Regression** | 0.9239 | 0.9360 | 0.9609 | 0.8930 | 0.9257 | 0.9437 | 0.9704 | 0.9741 | 0.0294 | 0.1070 | 40.36 |

### Final Calibrated Winner Performance (`LightGBM`, threshold = `0.55`)

| Split | Samples | Accuracy | Phishing Prec | Phishing Rec | Phishing F1 | Benign F1 | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Validation (`url_val`)** | `8,931` | `0.9628` | `0.9729` | `0.9431` | `0.9578` | `0.9668` | `0.9866` | `0.9883` | `0.0213` | `0.0569` |
| **Held-Out Test (`url_test`)** | `11,892` | **`0.9632`** | **`0.9737`** | **`0.9416`** | **`0.9573`** | **`0.9676`** | **`0.9871`** | **`0.9886`** | **`0.0199`** | **`0.0584`** |

- **Held-Out Test Confusion Matrix:** `TP (Phishing=0) = 4,915` | `FN = 305` | `FP = 133` | `TN (Benign=1) = 6,539`
- **Promotion Status:** `PROMOTED` (`v3.0.0`, `"All validation security gates passed."`, `"Test audit passed."`)

---

## 3. Model 2 — DOM Behaviour Classifier (`dom_behavior`, v3.0.0)

### Validation Candidate Comparison (`dom_val.csv`, `n = 730`, threshold = `0.50`)

Source: [`reports/dom_validation_comparison.csv`](../reports/dom_validation_comparison.csv)

| Candidate Model | CV Phishing F1 | Val Accuracy | Val Phishing Prec | Val Phishing Rec | Val Phishing F1 | Val Benign F1 | Val ROC AUC | Val PR AUC | Val FPR | Val FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **DOM XGBoost (Promoted `v3.0.0`)** | 0.8926 | **0.8986** | 0.9144 | **0.9007** | **0.9075** | **0.8879** | 0.9536 | 0.9659 | 0.1040 | **0.0993** | 12.71 |
| **DOM Random Forest** | 0.8958 | 0.8959 | 0.9098 | **0.9007** | 0.9052 | 0.8845 | **0.9579** | **0.9707** | 0.1101 | **0.0993** | 20.91 |
| **DOM LightGBM** | **0.8981** | 0.8877 | **0.9147** | 0.8784 | 0.8962 | 0.8776 | 0.9545 | 0.9670 | **0.1009** | 0.1216 | 32.87 |
| **DOM GradientBoosting** | 0.8839 | 0.8863 | 0.9103 | 0.8809 | 0.8953 | 0.8756 | 0.9447 | 0.9565 | 0.1070 | 0.1191 | 21.63 |
| **DOM Extra Trees** | 0.8835 | 0.8781 | 0.9046 | 0.8710 | 0.8875 | 0.8670 | 0.9474 | 0.9605 | 0.1131 | 0.1290 | 18.24 |

### Final Calibrated Winner Performance (`DOM XGBoost`, threshold = `0.65`)

| Split | Samples | Accuracy | Phishing Prec | Phishing Rec | Phishing F1 | Benign F1 | ROC AUC | PR AUC | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Validation (`dom_val`)** | `730` | `0.8836` | `0.9392` | `0.8437` | `0.8889` | `0.8777` | `0.9536` | `0.9659` | `0.0673` | `0.1563` |
| **Held-Out Test (`dom_test`)** | `968` | **`0.8729`** | **`0.9112`** | **`0.8418`** | **`0.8751`** | **`0.8707`** | **`0.9412`** | **`0.9422`** | `0.0921` | `0.1582` |
| **Domain-Disjoint Temporal (`dom_temporal_test`)** | `1,080` | `0.7565` | `0.8029` | `0.5185` | `0.6301` | `0.8185` | `0.8481` | `0.8024` | `0.0849` | `0.4815` |

- **Held-Out Test Confusion Matrix:** `TP (Phishing=0) = 431` | `FN = 81` | `FP = 42` | `TN (Benign=1) = 414`
- **Promotion Status:** `PROMOTED` (`v3.0.0`, `"All validation security gates passed."`, read-only audit note `"Test audit note: FPR 0.0921 > 0.08"`).

