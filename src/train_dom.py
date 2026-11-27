"""
src/train_dom.py — Model 2: DOM Behaviour Classifier Training, Temporal & Domain-Grouped Validation

Trains and evaluates Random Forest, HistGradientBoosting, and XGBoost exclusively
on separated DOM behaviour features (data/processed/dom_train/val/test.csv +
chronological dom_temporal_test.csv).
"""

from __future__ import annotations

import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import verify_domain_disjoint
from src.dom_features import DOM_FEATURE_COLUMNS
from src.evaluate import evaluate_model
from src.model_registry import register_model_bundle
from src.utils import setup_logger

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    import mlflow
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False

MODEL_VERSION = "v2.0.0"
PROCESSED_DIR = os.path.join("data", "processed")


def _prepare_dom_xy(df: pd.DataFrame):
    X = df[DOM_FEATURE_COLUMNS].copy()
    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)
    y = df["binary_label"].astype(int)
    return X, y


def main():
    logger = setup_logger()
    logger.info("Initializing DOM Behaviour Classifier (Model 2) training pipeline...")

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

    models_dict = {
        "DOM Random Forest": RandomForestClassifier(
            n_estimators=220, random_state=42, n_jobs=-1, max_depth=14, min_samples_leaf=2, class_weight="balanced"
        ),
        "DOM HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=180, max_depth=5, learning_rate=0.05, min_samples_leaf=8, l2_regularization=1.0,
            class_weight="balanced", random_state=42,
        ),
        "DOM GradientBoosting": GradientBoostingClassifier(
            n_estimators=160, max_depth=3, learning_rate=0.05, min_samples_leaf=4, subsample=0.85, random_state=42
        ),
    }
    if XGBOOST_AVAILABLE:
        models_dict["DOM XGBoost"] = XGBClassifier(
            n_estimators=180, random_state=42, n_jobs=-1, eval_metric="logloss",
            max_depth=4, learning_rate=0.05, min_child_weight=2, subsample=0.85, colsample_bytree=0.8,
            reg_alpha=0.5, reg_lambda=2.0,
        )

    if MLFLOW_AVAILABLE:
        os.makedirs("mlruns", exist_ok=True)
        mlflow.set_tracking_uri("sqlite:///mlruns/mlflow.db")
        mlflow.set_experiment("WebsiteSafety_DOM_Behaviour_Model")

    results = []
    trained = {}
    sgkf = StratifiedGroupKFold(n_splits=5)
    sample_weights_all = compute_sample_weight("balanced", y_train)

    for model_name, model in models_dict.items():
        logger.info(f"Training {model_name}...")
        t0 = time.time()

        cv_f1s = []
        use_sample_weight = not hasattr(model, "class_weight")
        for tr_i, va_i in sgkf.split(X_train, y_train, groups=groups_train):
            cv_m = clone(model)
            if use_sample_weight:
                cv_w = compute_sample_weight("balanced", y_train.iloc[tr_i])
                cv_m.fit(X_train.iloc[tr_i], y_train.iloc[tr_i], sample_weight=cv_w)
            else:
                cv_m.fit(X_train.iloc[tr_i], y_train.iloc[tr_i])
            cv_f1s.append(float(f1_score(y_train.iloc[va_i], cv_m.predict(X_train.iloc[va_i]), zero_division=0)))
        cv_f1_mean = float(np.mean(cv_f1s))

        if use_sample_weight:
            model.fit(X_train, y_train, sample_weight=sample_weights_all)
        else:
            model.fit(X_train, y_train)
        train_time = time.time() - t0

        val_metrics = evaluate_model(model, X_val, y_val, f"{model_name} Val", logger)
        test_metrics = evaluate_model(model, X_test, y_test, model_name, logger)
        temp_f1 = np.nan
        if X_temp is not None and y_temp is not None:
            temp_metrics = evaluate_model(model, X_temp, y_temp, f"{model_name} Temporal", logger)
            temp_f1 = temp_metrics["F1 Score"]

        row = {
            "Model Name": model_name,
            "CV F1 (Domain-Grouped)": round(cv_f1_mean, 4),
            "Val F1": round(val_metrics["F1 Score"], 4),
            "Temporal F1": round(temp_f1, 4) if not np.isnan(temp_f1) else np.nan,
            "Accuracy": test_metrics["Accuracy"],
            "Precision": test_metrics["Precision"],
            "Recall": test_metrics["Recall"],
            "F1 Score": test_metrics["F1 Score"],
            "ROC AUC": test_metrics["ROC AUC"],
            "PR AUC": test_metrics["PR AUC"],
            "FPR": test_metrics["FPR"],
            "FNR": test_metrics["FNR"],
            "Training Time (s)": round(train_time, 3),
        }
        results.append(row)
        trained[model_name] = model

        if MLFLOW_AVAILABLE:
            with mlflow.start_run(run_name=f"dom_{model_name}_{MODEL_VERSION}"):
                mlflow.log_params({"role": "dom_behavior", "algorithm": model_name, "version": MODEL_VERSION, "n_features": len(DOM_FEATURE_COLUMNS)})
                mlflow.log_metrics({
                    "cv_f1": cv_f1_mean,
                    "val_f1": val_metrics["F1 Score"],
                    "test_f1": test_metrics["F1 Score"],
                    "test_roc_auc": test_metrics["ROC AUC"],
                    "test_pr_auc": test_metrics["PR AUC"],
                    "test_fpr": test_metrics["FPR"],
                    "test_fnr": test_metrics["FNR"],
                })

    comp_df = pd.DataFrame(results).sort_values(by=["F1 Score", "ROC AUC"], ascending=False)
    comp_df.to_csv(os.path.join("reports", "dom_model_comparison.csv"), index=False)
    logger.info(f"\nDOM Model Comparison (Domain-Grouped Test):\n{comp_df.to_string(index=False)}")

    best_row = comp_df.iloc[0]
    best_name = str(best_row["Model Name"])
    best_model = trained[best_name]

    lineage = {
        "train_rows": int(len(train_df)),
        "val_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
        "sources": train_df["source"].value_counts().to_dict() if "source" in train_df.columns else {},
        "split_strategy": "domain_grouped_and_temporal",
    }
    meta = register_model_bundle(
        model_role="dom_behavior",
        version=MODEL_VERSION,
        model_obj=best_model,
        feature_columns=DOM_FEATURE_COLUMNS,
        metrics={k: float(v) if isinstance(v, (int, float, np.floating)) else v for k, v in best_row.to_dict().items() if k != "Model Name"},
        model_name=best_name,
        dataset_lineage=lineage,
        active_model_filename="dom_model.pkl",
        active_features_filename="dom_feature_columns.pkl",
    )
    logger.info(f"Registered DOM model {best_name} ({MODEL_VERSION}) | promoted={meta['promotion_passed']}")


if __name__ == "__main__":
    main()
