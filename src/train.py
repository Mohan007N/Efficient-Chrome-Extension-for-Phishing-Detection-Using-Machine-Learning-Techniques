"""
src/train.py — Model 1: URL Risk Classifier Leak-Free Training, Calibration & Thresholding (v3.0)

Strict Pipeline (Zero Test-Set Leakage):
1. Load domain-disjoint train / val / test partitions (`verify_domain_disjoint`).
2. Compare candidates (`Logistic Regression`, `Random Forest`, `HistGradientBoosting`,
   `XGBoost`, `LightGBM`) using training-only StratifiedGroupKFold CV and calibrated
   probabilities evaluated strictly on `val`.
3. Select winner ONLY using Validation metrics (Phishing F1, ROC AUC, low FPR).
4. Optimize phishing probability operating threshold strictly on `val`.
5. Evaluate the SINGLE selected, calibrated model ONCE on the untouched held-out `test` split.
6. Register atomically in `models/registry/` with SHA-256 checksums and promotion gates.
"""

from __future__ import annotations

import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import verify_domain_disjoint
from src.evaluate import (
    CLASS_MAPPING,
    CLASS_PHISHING,
    evaluate_model,
    get_class_probabilities,
    optimize_phishing_threshold,
    plot_correlation_heatmap,
    predict_with_threshold,
)
from src.features import URL_FEATURE_COLUMNS, validate_url_feature_schema
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


def _prepare_url_xy(df: pd.DataFrame, encoder: OrdinalEncoder | None = None, fit_encoder: bool = False):
    validate_url_feature_schema(df, URL_FEATURE_COLUMNS)
    X = df[URL_FEATURE_COLUMNS].copy()
    X["tld"] = X["tld"].fillna("com").astype(str).str.lower().str.strip()
    if fit_encoder:
        encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        X[["tld"]] = encoder.fit_transform(X[["tld"]])
    else:
        assert encoder is not None
        X[["tld"]] = encoder.transform(X[["tld"]])
    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)
    y = df["binary_label"].astype(int)
    return X, y, encoder


def main():
    logger = setup_logger()
    logger.info("Initializing WebShield v3.0 URL Risk Classifier (leak-free calibration pipeline)...")

    train_path = os.path.join(PROCESSED_DIR, "url_train.csv")
    val_path = os.path.join(PROCESSED_DIR, "url_val.csv")
    test_path = os.path.join(PROCESSED_DIR, "url_test.csv")

    if not (os.path.exists(train_path) and os.path.exists(val_path) and os.path.exists(test_path)):
        from src.build_datasets import build_all_datasets
        build_all_datasets()

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)
    verify_domain_disjoint(train_df, val_df, test_df, group_col="root_domain")

    X_train, y_train, tld_encoder = _prepare_url_xy(train_df, fit_encoder=True)
    X_val, y_val, _ = _prepare_url_xy(val_df, encoder=tld_encoder)
    X_test, y_test, _ = _prepare_url_xy(test_df, encoder=tld_encoder)
    groups_train = train_df["root_domain"].fillna("unknown").astype(str).to_numpy()

    plot_correlation_heatmap(X_train, save_dir="reports")

    base_candidates = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=600, class_weight="balanced", random_state=42)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=180, random_state=42, n_jobs=-1, max_depth=20, min_samples_leaf=4, max_features="sqrt", class_weight="balanced"
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=250, max_depth=8, learning_rate=0.07, min_samples_leaf=20, l2_regularization=2.0, class_weight="balanced", random_state=42
        ),
    }
    if XGBOOST_AVAILABLE:
        base_candidates["XGBoost"] = XGBClassifier(
            n_estimators=260, random_state=42, n_jobs=-1, eval_metric="logloss",
            max_depth=7, learning_rate=0.07, min_child_weight=5, subsample=0.85,
            colsample_bytree=0.75, reg_alpha=1.0, reg_lambda=3.0,
        )
    if LIGHTGBM_AVAILABLE:
        base_candidates["LightGBM"] = LGBMClassifier(
            n_estimators=260, learning_rate=0.07, num_leaves=63, subsample=0.85,
            colsample_bytree=0.8, reg_alpha=0.5, reg_lambda=2.0, class_weight="balanced",
            random_state=42, n_jobs=-1, verbose=-1,
        )

    if MLFLOW_AVAILABLE:
        os.makedirs("mlruns", exist_ok=True)
        mlflow.set_tracking_uri("sqlite:///mlruns/mlflow.db")
        mlflow.set_experiment("WebsiteSafety_URL_Risk_v3")

    val_results = []
    calibrated_models = {}
    sgkf = StratifiedGroupKFold(n_splits=3)

    for model_name, base_est in base_candidates.items():
        logger.info(f"Training & calibrating URL candidate: {model_name} (train-only CV + sigmoid calibration)...")
        t0 = time.time()

        cv_phish_f1s = []
        for tr_i, va_i in sgkf.split(X_train, y_train, groups=groups_train):
            cv_m = clone(base_est)
            cv_m.fit(X_train.iloc[tr_i], y_train.iloc[tr_i])
            p_phish_cv, _ = get_class_probabilities(cv_m, X_train.iloc[va_i])
            pred_cv = predict_with_threshold(p_phish_cv, threshold=0.5)
            cv_phish_f1s.append(float(f1_score(y_train.iloc[va_i], pred_cv, pos_label=CLASS_PHISHING, zero_division=0)))
        cv_f1_mean = float(np.mean(cv_phish_f1s))

        # Probability calibration performed strictly inside train split (`cv=3`) so validation remains untouched
        cal_model = CalibratedClassifierCV(estimator=clone(base_est), method="sigmoid", cv=3)
        cal_model.fit(X_train, y_train)
        train_time = time.time() - t0

        val_metrics = evaluate_model(cal_model, X_val, y_val, f"url_val_{model_name}", logger, threshold=0.5)

        val_row = {
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
        }
        val_results.append(val_row)
        calibrated_models[model_name] = (cal_model, val_metrics)

    val_comp_df = pd.DataFrame(val_results).sort_values(
        by=["Val Phishing F1", "Val ROC AUC", "Val FPR"], ascending=[False, False, True]
    )
    val_comp_df.to_csv(os.path.join("reports", "url_validation_comparison.csv"), index=False)
    logger.info(f"\nURL Candidate Comparison (VALIDATION ONLY — Zero Test Leakage):\n{val_comp_df.to_string(index=False)}")

    # Select winner strictly from Validation leaderboard
    best_val_row = val_comp_df.iloc[0]
    best_name = str(best_val_row["Model Name"])
    winner_model, _ = calibrated_models[best_name]

    # Optimize phishing decision threshold strictly on Validation split
    prob_phish_val, _ = get_class_probabilities(winner_model, X_val)
    best_threshold, threshold_info = optimize_phishing_threshold(y_val, prob_phish_val, min_phishing_recall=0.92, max_fpr=0.06)
    val_tuned_metrics = evaluate_model(winner_model, X_val, y_val, f"url_val_selected_{best_name}", logger, threshold=best_threshold)
    logger.info(f"Selected URL winner on validation: {best_name} | optimized threshold={best_threshold:.2f} | info={threshold_info}")

    # Single untouched held-out Test evaluation on ONLY the selected winner
    test_metrics = evaluate_model(winner_model, X_test, y_test, f"url_test_{best_name}", logger, threshold=best_threshold)

    final_row = {
        "Selected Model": best_name,
        "Positive Class": "0 (Phishing / Malicious)",
        "Calibrated": True,
        "Operating Threshold": best_threshold,
        "CV Phishing F1": float(best_val_row["CV Phishing F1"]),
        "Val Phishing F1": val_tuned_metrics["Phishing F1"],
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
    pd.DataFrame([final_row]).to_csv(os.path.join("reports", "model_comparison_results.csv"), index=False)

    if MLFLOW_AVAILABLE:
        with mlflow.start_run(run_name=f"url_winner_{best_name}_{MODEL_VERSION}"):
            mlflow.log_params({
                "role": "url_risk",
                "algorithm": best_name,
                "version": MODEL_VERSION,
                "n_features": len(URL_FEATURE_COLUMNS),
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
        "sources": train_df["source"].value_counts().to_dict() if "source" in train_df.columns else {},
        "split_strategy": "domain_grouped_GroupShuffleSplit_val_only_selection",
    }
    lineage["dataset_fingerprint"] = compute_dataset_fingerprint(lineage)

    meta = register_model_bundle(
        model_role="url_risk",
        version=MODEL_VERSION,
        model_obj=winner_model,
        feature_columns=URL_FEATURE_COLUMNS,
        validation_metrics=val_tuned_metrics,
        test_metrics=test_metrics,
        model_name=best_name,
        dataset_lineage=lineage,
        class_mapping=CLASS_MAPPING,
        threshold=best_threshold,
        calibrated=True,
        training_config={"cv": "StratifiedGroupKFold(3)", "calibration": "sigmoid(cv=3)", "threshold_rule": threshold_info["methodology"]},
        encoders={"tld": tld_encoder},
        active_model_filename="url_model.pkl",
        active_features_filename="url_feature_columns.pkl",
        active_encoders_filename="url_encoders.pkl",
        legacy_alias_filename="best_phishing_model.pkl",
    )
    logger.info(f"Registered URL winner {best_name} ({MODEL_VERSION}) | promoted={meta['promotion_passed']} | notes={meta['promotion_gate_notes']}")


if __name__ == "__main__":
    main()
