"""
src/train_dom.py — Model 2: DOM Behaviour Classifier Leak-Free Training & Calibration (v3.0)

Strict Pipeline (Zero Test-Set Leakage):
1. Compare exact Phase 3.2 DOM candidates (`DOM Random Forest`, `DOM Extra Trees`,
   `DOM GradientBoosting`, `DOM XGBoost`) on training CV + Validation ONLY.
2. Calibrate probabilities inside `train` split (`CalibratedClassifierCV(method='sigmoid', cv=3)`).
3. Select winner and tune phishing probability operating threshold strictly on `val`.
4. Evaluate the SINGLE final selected model ONCE on untouched `dom_test.csv` and `dom_temporal_test.csv`.
5. Register atomically in `models/registry/` with SHA-256 checksums and promotion gates.
"""

from __future__ import annotations

import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import verify_domain_disjoint
from src.dom_features import DOM_FEATURE_COLUMNS, validate_dom_feature_schema
from src.evaluate import (
    CLASS_MAPPING,
    CLASS_PHISHING,
    evaluate_model,
    get_class_probabilities,
    optimize_phishing_threshold,
    predict_with_threshold,
)
from src.model_registry import compute_dataset_fingerprint, register_model_bundle
from src.utils import setup_logger

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

try:
    import mlflow
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False

MODEL_VERSION = "v3.0.0"
PROCESSED_DIR = os.path.join("data", "processed")


def _prepare_dom_xy(df: pd.DataFrame):
    validate_dom_feature_schema(df, DOM_FEATURE_COLUMNS)
    X = df[DOM_FEATURE_COLUMNS].copy()
    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)
    y = df["binary_label"].astype(int)
    return X, y


def main():
    logger = setup_logger()
    logger.info("Initializing WebShield v3.0 DOM Behaviour Classifier (leak-free calibration pipeline)...")

    train_path = os.path.join(PROCESSED_DIR, "dom_train.csv")
    val_path = os.path.join(PROCESSED_DIR, "dom_val.csv")
    test_path = os.path.join(PROCESSED_DIR, "dom_test.csv")
    temp_path = os.path.join(PROCESSED_DIR, "dom_temporal_test.csv")

    if not (os.path.exists(train_path) and os.path.exists(val_path) and os.path.exists(test_path)):
        from src.build_datasets import build_all_datasets
        build_all_datasets()

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)
    verify_domain_disjoint(train_df, val_df, test_df, group_col="root_domain")

    X_train, y_train = _prepare_dom_xy(train_df)
    X_val, y_val = _prepare_dom_xy(val_df)
    X_test, y_test = _prepare_dom_xy(test_df)
    groups_train = train_df["root_domain"].fillna("unknown").astype(str).to_numpy()

    X_temp, y_temp = (None, None)
    if os.path.exists(temp_path):
        temp_df = pd.read_csv(temp_path)
        if not temp_df.empty:
            X_temp, y_temp = _prepare_dom_xy(temp_df)

    # Phase 3.2 DOM candidate models (note class 0=Phishing positive ratio balanced cleanly)
    n_phish = max(1, int((y_train == 0).sum()))
    n_benign = max(1, int((y_train == 1).sum()))
    base_candidates = {
        "DOM Random Forest": RandomForestClassifier(
            n_estimators=260, random_state=42, n_jobs=-1, max_depth=16, min_samples_leaf=2, class_weight="balanced"
        ),
        "DOM Extra Trees": ExtraTreesClassifier(
            n_estimators=260, random_state=42, n_jobs=-1, max_depth=16, min_samples_leaf=2, class_weight="balanced"
        ),
        "DOM GradientBoosting": GradientBoostingClassifier(
            n_estimators=180, max_depth=3, learning_rate=0.05, min_samples_leaf=4, subsample=0.85, random_state=42
        ),
    }
    if XGBOOST_AVAILABLE:
        base_candidates["DOM XGBoost"] = XGBClassifier(
            n_estimators=300, random_state=42, n_jobs=-1, eval_metric="logloss",
            max_depth=6, learning_rate=0.04, min_child_weight=2, subsample=0.85, colsample_bytree=0.85,
            reg_alpha=0.2, reg_lambda=1.5,
            scale_pos_weight=round(n_phish / n_benign, 3),
        )
    if LIGHTGBM_AVAILABLE:
        base_candidates["DOM LightGBM"] = LGBMClassifier(
            n_estimators=320, random_state=42, n_jobs=-1, verbose=-1,
            num_leaves=45, learning_rate=0.035, min_child_samples=12,
            subsample=0.85, subsample_freq=1, colsample_bytree=0.80,
            reg_lambda=1.0, class_weight="balanced",
        )

    if MLFLOW_AVAILABLE:
        os.makedirs("mlruns", exist_ok=True)
        mlflow.set_tracking_uri("sqlite:///mlruns/mlflow.db")
        mlflow.set_experiment("WebsiteSafety_DOM_Behaviour_v3")

    val_results = []
    calibrated_models = {}
    sgkf = StratifiedGroupKFold(n_splits=5)

    for model_name, base_est in base_candidates.items():
        logger.info(f"Training & calibrating DOM candidate: {model_name}...")
        t0 = time.time()

        cv_phish_f1s = []
        use_sw = isinstance(base_est, GradientBoostingClassifier)
        for tr_i, va_i in sgkf.split(X_train, y_train, groups=groups_train):
            cv_m = clone(base_est)
            if use_sw:
                cv_m.fit(X_train.iloc[tr_i], y_train.iloc[tr_i], sample_weight=compute_sample_weight("balanced", y_train.iloc[tr_i]))
            else:
                cv_m.fit(X_train.iloc[tr_i], y_train.iloc[tr_i])
            p_phish_cv, _ = get_class_probabilities(cv_m, X_train.iloc[va_i])
            pred_cv = predict_with_threshold(p_phish_cv, threshold=0.5)
            cv_phish_f1s.append(float(f1_score(y_train.iloc[va_i], pred_cv, pos_label=CLASS_PHISHING, zero_division=0)))
        cv_f1_mean = float(np.mean(cv_phish_f1s))

        cal_model = CalibratedClassifierCV(estimator=clone(base_est), method="isotonic", cv=5)
        if use_sw:
            cal_model.fit(X_train, y_train, sample_weight=compute_sample_weight("balanced", y_train))
        else:
            cal_model.fit(X_train, y_train)
        train_time = time.time() - t0

        val_metrics = evaluate_model(cal_model, X_val, y_val, f"dom_val_{model_name}", logger, threshold=0.5)

        val_results.append({
            "Model Name": model_name,
            "CV Phishing F1": round(cv_f1_mean, 4),
            "Val Accuracy": val_metrics["Accuracy"],
            "Val Phishing Precision": val_metrics["Phishing Precision"],
            "Val Phishing Recall": val_metrics["Phishing Recall"],
            "Val Phishing F1": val_metrics["Phishing F1"],
            "Val Benign F1": val_metrics["Benign F1"],
            "Val ROC AUC": val_metrics["ROC AUC"],
            "Val PR AUC": val_metrics["PR AUC"],
            "Val FPR": val_metrics["FPR"],
            "Val FNR": val_metrics["FNR"],
            "Training Time (s)": round(train_time, 3),
        })
        calibrated_models[model_name] = (cal_model, val_metrics)

    val_comp_df = pd.DataFrame(val_results).sort_values(
        by=["Val Phishing F1", "Val ROC AUC", "Val FPR"], ascending=[False, False, True]
    )
    val_comp_df.to_csv(os.path.join("reports", "dom_validation_comparison.csv"), index=False)
    logger.info(f"\nDOM Candidate Comparison (VALIDATION ONLY — Zero Test Leakage):\n{val_comp_df.to_string(index=False)}")

    # Select winner strictly from Validation metrics
    best_val_row = val_comp_df.iloc[0]
    best_name = str(best_val_row["Model Name"])
    winner_model, _ = calibrated_models[best_name]

    # Tune decision threshold strictly on Validation split (target FPR <= 0.075 under <= 0.08 security gate)
    prob_phish_val, _ = get_class_probabilities(winner_model, X_val)
    best_threshold, threshold_info = optimize_phishing_threshold(y_val, prob_phish_val, min_phishing_recall=0.82, max_fpr=0.075)
    val_tuned_metrics = evaluate_model(winner_model, X_val, y_val, f"dom_val_selected_{best_name}", logger, threshold=best_threshold)
    logger.info(f"Selected DOM winner on validation: {best_name} | optimized threshold={best_threshold:.2f} | info={threshold_info}")

    # Evaluate selected winner ONCE on untouched held-out test set & chronological temporal split
    test_metrics = evaluate_model(winner_model, X_test, y_test, f"dom_test_{best_name}", logger, threshold=best_threshold)
    temp_metrics = {}
    if X_temp is not None and y_temp is not None:
        temp_metrics = evaluate_model(winner_model, X_temp, y_temp, f"dom_temporal_{best_name}", logger, threshold=best_threshold)

    final_row = {
        "Selected Model": best_name,
        "Positive Class": "0 (Phishing / Malicious)",
        "Calibrated": True,
        "Operating Threshold": best_threshold,
        "CV Phishing F1": float(best_val_row["CV Phishing F1"]),
        "Val Phishing F1": val_tuned_metrics["Phishing F1"],
        "Temporal Phishing F1": temp_metrics.get("Phishing F1", np.nan),
        "Accuracy": test_metrics["Accuracy"],
        "Phishing Precision": test_metrics["Phishing Precision"],
        "Phishing Recall": test_metrics["Phishing Recall"],
        "Phishing F1": test_metrics["Phishing F1"],
        "Benign Precision": test_metrics["Benign Precision"],
        "Benign Recall": test_metrics["Benign Recall"],
        "Benign F1": test_metrics["Benign F1"],
        "Precision": test_metrics["Phishing Precision"],
        "Recall": test_metrics["Phishing Recall"],
        "F1 Score": test_metrics["Phishing F1"],
        "ROC AUC": test_metrics["ROC AUC"],
        "PR AUC": test_metrics["PR AUC"],
        "FPR": test_metrics["FPR"],
        "FNR": test_metrics["FNR"],
        "Training Time (s)": float(best_val_row["Training Time (s)"]),
    }
    pd.DataFrame([final_row]).to_csv(os.path.join("reports", "dom_model_comparison.csv"), index=False)

    if MLFLOW_AVAILABLE:
        with mlflow.start_run(run_name=f"dom_winner_{best_name}_{MODEL_VERSION}"):
            mlflow.log_params({
                "role": "dom_behavior",
                "algorithm": best_name,
                "version": MODEL_VERSION,
                "n_features": len(DOM_FEATURE_COLUMNS),
                "threshold": best_threshold,
                "calibrated": True,
            })
            mlflow.log_metrics({
                "val_phishing_f1": val_tuned_metrics["Phishing F1"],
                "test_accuracy": test_metrics["Accuracy"],
                "test_phishing_f1": test_metrics["Phishing F1"],
                "test_benign_f1": test_metrics["Benign F1"],
                "test_roc_auc": test_metrics["ROC AUC"],
                "test_pr_auc": test_metrics["PR AUC"],
                "test_fpr": test_metrics["FPR"],
                "test_fnr": test_metrics["FNR"],
            })

    lineage = {
        "train_rows": int(len(train_df)),
        "val_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
        "temporal_rows": int(len(y_temp)) if y_temp is not None else 0,
        "sources": train_df["source"].value_counts().to_dict() if "source" in train_df.columns else {},
        "split_strategy": "domain_grouped_and_temporal_val_only_selection",
    }
    lineage["dataset_fingerprint"] = compute_dataset_fingerprint(lineage)

    meta = register_model_bundle(
        model_role="dom_behavior",
        version=MODEL_VERSION,
        model_obj=winner_model,
        feature_columns=DOM_FEATURE_COLUMNS,
        validation_metrics=val_tuned_metrics,
        test_metrics=test_metrics,
        model_name=best_name,
        dataset_lineage=lineage,
        class_mapping=CLASS_MAPPING,
        threshold=best_threshold,
        calibrated=True,
        training_config={"cv": "StratifiedGroupKFold(5)", "calibration": "isotonic(cv=5)", "threshold_rule": threshold_info["methodology"]},
        active_model_filename="dom_model.pkl",
        active_features_filename="dom_feature_columns.pkl",
    )
    logger.info(f"Registered DOM winner {best_name} ({MODEL_VERSION}) | promoted={meta['promotion_passed']} | notes={meta['promotion_gate_notes']}")


if __name__ == "__main__":
    main()
