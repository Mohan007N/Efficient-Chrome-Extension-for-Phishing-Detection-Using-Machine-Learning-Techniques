# Model Architecture, Evaluation & MLOps Registry Documentation

## 1. Multi-Model Security Architecture

Rather than relying on a single binary classifier that collapses insecure HTTP transport, phishing, payment scams, and malware into one label, the upgraded architecture in [`backend/predictor.py`](../backend/predictor.py) and [`backend/risk_engine.py`](../backend/risk_engine.py) coordinates five specialized analytical models:

1. **Model 1 — URL Risk Classifier (`src/train.py`, role `url_risk`)**: Supervised ensemble trained strictly on 27 separated lexical, entropy, encoding, port, TLD, and typosquatting URL features (`URL_FEATURE_COLUMNS`).
2. **Model 2 — DOM Behaviour Classifier (`src/train_dom.py`, role `dom_behavior`)**: Supervised ensemble trained on 36 DOM behaviour features (`DOM_FEATURE_COLUMNS`) covering credential forms, payment patterns, hidden iframes, deceptive links, popups, redirects, and inline JS obfuscation.
3. **Model 3 — Brand Impersonation Detector (`src/features.py`)**: Evaluates Punycode/IDN homographs, leet-speak substitution (`_DELEET_TABLE`), normalized edit distance against `PROTECTED_BRANDS`, and page-title vs. registered-domain mismatches (`compute_brand_impersonation_details`).
4. **Model 4 — Credential & Payment Risk Detector (`src/dom_features.py`, `src/web_forensics.py`)**: Inspects external/cross-domain login form actions (`evaluate_credential_and_payment_risk`), prepaid-only checkout traps, restrictive store-credit/no-refund clauses, free-webmail support addresses, and absent corporate identity signals (`analyze_storefront_forensics`).
5. **Model 5 — Threat Intelligence Engine (`backend/intel.py`)**: Combines compressed domain blocklists (`unauthorized_domains.json.gz`), Tranco popularity rank lookup (`tranco_top1m.json.gz`), SSRF-safe live fetch, and graceful RDAP/TLS metadata inspection.

All five outputs fuse inside [`HybridRiskEngine.assess`](../backend/risk_engine.py) into six separate dimensions:
- `connection_security` (HTTPS, mixed content, or unencrypted HTTP — never equated alone with phishing)
- `phishing_risk`
- `malware_risk`
- `credential_risk`
- `payment_risk`
- `deceptive_behavior_risk`

Standardized risk tiers are `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, and `UNKNOWN`. Statistical ML probabilities (`url_model_threat_probability`, `dom_model_threat_probability`) remain explicitly separated from the multi-factor `heuristic_risk_index` (`0–100`).

---

## 2. Model 1 Benchmark — URL Risk Classifier

Evaluated on `data/processed/url_test.csv` (`12,308` held-out URLs across `11,681` disjoint root domains, after domain-grouped CV on `42,668` training URLs and validation on `6,129` URLs; leading `www.` canonicalized prior to lexical feature computation so classifiers do not overfit to dataset crawl prefixes):

| Model | CV F1 (Grouped) | Val F1 | Test Accuracy | Test Precision | Test Recall | Test F1 | ROC AUC | PR AUC | FPR | FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **HistGradientBoosting** *(Promoted `v2.0.0`)* | **0.9694** | 0.9696 | **0.9686** | 0.9538 | 0.9851 | **0.9692** | 0.9884 | **0.9917** | 0.0149 | 0.0478 | 7.286 |
| **XGBoost** | 0.9693 | **0.9698** | 0.9685 | 0.9541 | 0.9844 | 0.9690 | **0.9886** | 0.9916 | 0.0156 | 0.0475 | 6.154 |
| **Random Forest** | 0.9664 | 0.9697 | 0.9682 | **0.9543** | 0.9836 | 0.9687 | 0.9870 | 0.9908 | 0.0164 | **0.0472** | 7.106 |
| **Decision Tree** | 0.9621 | 0.9672 | 0.9638 | 0.9492 | 0.9800 | 0.9644 | 0.9808 | 0.9821 | 0.0200 | 0.0525 | 4.644 |
| **Logistic Regression** | 0.9489 | 0.9496 | 0.9482 | 0.9173 | **0.9854** | 0.9502 | 0.9781 | 0.9846 | **0.0146** | 0.0890 | 3.938 |

*Source: [`reports/model_comparison_results.csv`](../reports/model_comparison_results.csv).*

---

## 3. Model 2 Benchmark — DOM Behaviour Classifier

Evaluated on `data/processed/dom_test.csv` (`159` held-out HTML documents across `142` disjoint root domains, after 5-fold domain-grouped CV on `572` training pages and validation on `82` pages) plus `202` chronological records in `data/processed/dom_temporal_test.csv`. Training uses class-balanced sample/class weights to handle class skew cleanly:

| Model | CV F1 (Grouped) | Val F1 | Temporal F1 | Test Accuracy | Test Precision | Test Recall | Test F1 | ROC AUC | PR AUC | FPR | FNR | Train Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **DOM Random Forest** *(Promoted `v2.0.0`)* | **0.8665** | **0.9455** | 0.9536 | **0.8365** | 0.8545 | **0.9038** | **0.8785** | **0.9030** | 0.8490 | **0.0962** | 0.2909 | 2.271 |
| **DOM HistGradientBoosting** | 0.8649 | **0.9455** | **0.9671** | 0.8302 | 0.8598 | 0.8846 | 0.8720 | 0.8939 | 0.8398 | 0.1154 | 0.2727 | 2.503 |
| **DOM XGBoost** | 0.8638 | **0.9455** | 0.9404 | 0.8302 | 0.8667 | 0.8750 | 0.8708 | 0.8976 | **0.8492** | 0.1250 | 0.2545 | 0.757 |
| **DOM GradientBoosting** | 0.8643 | 0.9259 | 0.9502 | 0.8239 | **0.8725** | 0.8558 | 0.8641 | 0.8993 | 0.8369 | 0.1442 | **0.2364** | 1.303 |

*Source: [`reports/dom_model_comparison.csv`](../reports/dom_model_comparison.csv).*

---

## 4. Model Registry, Promotion Gates & Experiment Tracking

- **MLflow Tracking**: Both `src/train.py` and `src/train_dom.py` log experiments, hyperparameters, CV F1, validation F1, test F1, ROC AUC, PR AUC, FPR, and FNR to SQLite-backed tracking at `sqlite:///mlruns/mlflow.db`.
- **Promotion Gates (`src/model_registry.py`)**: Candidate models must satisfy `DEFAULT_PROMOTION_GATES`:
  - `F1 Score >= 0.82`
  - `ROC AUC >= 0.88`
  - `FPR <= 0.12`
- **Active Registry Manifest**: [`models/registry/active_manifest.json`](../models/registry/active_manifest.json) records the active promoted bundles (`url_risk` `v2.0.0` = `HistGradientBoosting`; `dom_behavior` `v2.0.0` = `DOM Random Forest`) alongside exact dataset lineage, feature column lists, timestamps, and gate verification notes. Active runtime pointers are stored at `models/url_model.pkl`, `models/url_feature_columns.pkl`, `models/url_encoders.pkl`, `models/dom_model.pkl`, and `models/dom_feature_columns.pkl`.

---

## 5. Explainable AI (XAI)

[`backend/explainer.py`](../backend/explainer.py) generates transparent explanations for `/explain`:
1. **Local SHAP Attributions**: `compute_shap_attributions()` invokes `shap.TreeExplainer` for promoted tree-based URL and DOM models (gracefully falling back to `feature_importances_` when needed).
2. **Deterministic Multi-Layer Evidence**: Combines SHAP drivers with URL/brand/DOM/credential/payment rules and threat-intel hits.
3. **Optional Groq LLM Synthesis**: When `GROQ_API_KEY` is configured on the backend, synthesizes concise human-readable security guidance; never embeds keys inside client extension code.

