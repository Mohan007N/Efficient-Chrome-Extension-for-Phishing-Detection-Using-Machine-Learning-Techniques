"""
src/train.py — Model 1: URL Risk Classifier Training, Domain-Grouped CV & MLflow Tracking

Evaluates Logistic Regression, Decision Tree, Random Forest, HistGradientBoosting,
and XGBoost strictly on separated URL features (data/processed/url_train/val/test.csv)
with domain-grouped cross-validation and MLflow experiment logging.
"""

from __future__ import annotations

import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import verify_domain_disjoint
from src.evaluate import evaluate_model, plot_correlation_heatmap
from src.features import URL_FEATURE_COLUMNS
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


def _prepare_url_xy(df: pd.DataFrame, encoder: OrdinalEncoder | None = None, fit_encoder: bool = False):
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
    logger.info("Initializing URL Risk Classifier (Model 1) training pipeline...")

    train_path = os.path.join(PROCESSED_DIR, "url_train.csv")
    val_path = os.path.join(PROCESSED_DIR, "url_val.csv")
    test_path = os.path.join(PROCESSED_DIR, "url_test.csv")

    if not (os.path.exists(train_path) and os.path.exists(val_path) and os.path.exists(test_path)):
        from src.build_datasets import build_all_datasets
        logger.info("Processed URL datasets not found; running src/build_datasets.py...")
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

    models_dict = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=500, class_weight="balanced", random_state=42)),
        ]),
        "Decision Tree": DecisionTreeClassifier(
            random_state=42, max_depth=16, min_samples_leaf=8, min_samples_split=16
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=150, random_state=42, n_jobs=-1, max_depth=20, min_samples_leaf=4, max_features="sqrt"
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=250, max_depth=8, learning_rate=0.08, min_samples_leaf=20, l2_regularization=2.0, random_state=42
        ),
    }
    if XGBOOST_AVAILABLE:
        models_dict["XGBoost"] = XGBClassifier(
            n_estimators=260, random_state=42, n_jobs=-1, eval_metric="logloss",
            max_depth=7, learning_rate=0.08, min_child_weight=5, subsample=0.8,
            colsample_bytree=0.7, reg_alpha=1.0, reg_lambda=3.0,
        )

    if MLFLOW_AVAILABLE:
        os.makedirs("mlruns", exist_ok=True)
        mlflow.set_tracking_uri("sqlite:///mlruns/mlflow.db")
        mlflow.set_experiment("WebsiteSafety_URL_Risk_Model")

    comparison_results = []
    trained_models = {}
    sgkf = StratifiedGroupKFold(n_splits=3)

    for model_name, model in models_dict.items():
        logger.info(f"Training URL model: {model_name}...")
        t0 = time.time()

        # Domain-grouped CV on train split
        cv_f1s = []
        for tr_i, va_i in sgkf.split(X_train, y_train, groups=groups_train):
            from sklearn.base import clone
            cv_m = clone(model)
            cv_m.fit(X_train.iloc[tr_i], y_train.iloc[tr_i])
            preds_cv = cv_m.predict(X_train.iloc[va_i])
            from sklearn.metrics import f1_score
            cv_f1s.append(float(f1_score(y_train.iloc[va_i], preds_cv, zero_division=0)))
        cv_f1_mean = float(np.mean(cv_f1s))

        model.fit(X_train, y_train)
        train_time = time.time() - t0

        val_metrics = evaluate_model(model, X_val, y_val, f"{model_name} URL Val", logger)
        test_metrics = evaluate_model(model, X_test, y_test, f"url_{model_name}", logger)

        row = {
            "Model Name": model_name,
            "CV F1 (Domain-Grouped)": round(cv_f1_mean, 4),
            "Val F1": round(val_metrics["F1 Score"], 4),
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
        comparison_results.append(row)
        trained_models[model_name] = model

        if MLFLOW_AVAILABLE:
            with mlflow.start_run(run_name=f"url_{model_name}_{MODEL_VERSION}"):
                mlflow.log_params({"role": "url_risk", "algorithm": model_name, "version": MODEL_VERSION, "n_features": len(URL_FEATURE_COLUMNS)})
                mlflow.log_metrics({
                    "cv_f1": cv_f1_mean,
                    "val_f1": val_metrics["F1 Score"],
                    "test_accuracy": test_metrics["Accuracy"],
                    "test_precision": test_metrics["Precision"],
                    "test_recall": test_metrics["Recall"],
                    "test_f1": test_metrics["F1 Score"],
                    "test_roc_auc": test_metrics["ROC AUC"],
                    "test_pr_auc": test_metrics["PR AUC"],
                    "test_fpr": test_metrics["FPR"],
                    "test_fnr": test_metrics["FNR"],
                })

    comp_df = pd.DataFrame(comparison_results).sort_values(by=["F1 Score", "ROC AUC"], ascending=False)
    comp_df.to_csv(os.path.join("reports", "model_comparison_results.csv"), index=False)
    logger.info(f"\nURL Model Comparison (Domain-Grouped Test):\n{comp_df.to_string(index=False)}")

    best_row = comp_df.iloc[0]
    best_name = str(best_row["Model Name"])
    best_model = trained_models[best_name]

    lineage = {
        "train_rows": int(len(train_df)),
        "val_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
        "sources": train_df["source"].value_counts().to_dict() if "source" in train_df.columns else {},
        "split_strategy": "domain_grouped_GroupShuffleSplit",
    }
    meta = register_model_bundle(
        model_role="url_risk",
        version=MODEL_VERSION,
        model_obj=best_model,
        feature_columns=URL_FEATURE_COLUMNS,
        metrics={k: float(v) if isinstance(v, (int, float, np.floating)) else v for k, v in best_row.to_dict().items() if k != "Model Name"},
        model_name=best_name,
        dataset_lineage=lineage,
        encoders={"tld": tld_encoder},
        active_model_filename="url_model.pkl",
        active_features_filename="url_feature_columns.pkl",
        active_encoders_filename="url_encoders.pkl",
        legacy_alias_filename="best_phishing_model.pkl",
    )
    logger.info(f"Registered URL model {best_name} ({MODEL_VERSION}) | promoted={meta['promotion_passed']}")


if __name__ == "__main__":
    main()
