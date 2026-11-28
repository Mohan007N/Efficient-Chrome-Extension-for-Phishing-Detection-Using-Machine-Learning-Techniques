"""
src/evaluate.py — Explicit Class-Mapped ML Evaluation, Calibration Thresholding & Plotting (v3.0)

Enforces strict semantic class mapping:
  0 = Phishing / Malicious (positive security target)
  1 = Benign / Legitimate

Never assumes index 0 or index 1 of predict_proba() without inspecting `model.classes_`.
Computes and reports both Phishing (0) and Benign (1) metrics explicitly.
"""

from __future__ import annotations

import logging
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

CLASS_PHISHING = 0
CLASS_BENIGN = 1
CLASS_MAPPING = {"0": "phishing_malicious", "1": "benign_legitimate"}


def resolve_class_indices(model) -> tuple[int, int]:
    """
    Inspect `model.classes_` and return `(phish_idx, benign_idx)` corresponding to
    class 0 (Phishing/Malicious) and class 1 (Benign/Legitimate).
    Raises ValueError if either required class is absent.
    """
    classes = getattr(model, "classes_", None)
    if classes is None:
        raise ValueError(f"Model {type(model).__name__} is missing required `classes_` attribute.")
    class_list = [int(c) for c in classes]
    if CLASS_PHISHING not in class_list or CLASS_BENIGN not in class_list:
        raise ValueError(
            f"Model {type(model).__name__} classes {class_list} missing required binary classes [0 (phishing), 1 (benign)]."
        )
    return class_list.index(CLASS_PHISHING), class_list.index(CLASS_BENIGN)


def get_class_probabilities(model, X) -> tuple[np.ndarray, np.ndarray]:
    """
    Return `(prob_phishing, prob_benign)` strictly indexed by `model.classes_`.
    """
    if not hasattr(model, "predict_proba"):
        preds = np.asarray(model.predict(X)).astype(int)
        prob_phish = np.where(preds == CLASS_PHISHING, 0.85, 0.15).astype(float)
        return prob_phish, 1.0 - prob_phish
    phish_idx, benign_idx = resolve_class_indices(model)
    probs = np.asarray(model.predict_proba(X), dtype=float)
    return probs[:, phish_idx], probs[:, benign_idx]


def predict_with_threshold(prob_phishing: np.ndarray, threshold: float = 0.5) -> np.ndarray:
    """Classify samples as Phishing (0) when prob_phishing >= threshold, else Benign (1)."""
    return np.where(np.asarray(prob_phishing, dtype=float) >= float(threshold), CLASS_PHISHING, CLASS_BENIGN)


def optimize_phishing_threshold(
    y_true,
    prob_phishing: np.ndarray,
    min_phishing_recall: float = 0.90,
    max_fpr: float = 0.08,
) -> tuple[float, dict]:
    """
    Tune phishing probability cutoff strictly on validation data.
    Maximizes Phishing F1 while enforcing `FPR <= max_fpr` and targeting
    `Phishing Recall >= min_phishing_recall` where achievable.
    """
    y_arr = np.asarray(y_true, dtype=int)
    p_arr = np.asarray(prob_phishing, dtype=float)
    y_phish_true = (y_arr == CLASS_PHISHING).astype(int)

    best_feasible = None
    best_under_fpr = None
    best_fallback = None

    for tau in np.round(np.linspace(0.20, 0.88, 69), 4):
        preds = predict_with_threshold(p_arr, threshold=float(tau))
        p_rec = float(recall_score(y_arr, preds, pos_label=CLASS_PHISHING, zero_division=0))
        p_prec = float(precision_score(y_arr, preds, pos_label=CLASS_PHISHING, zero_division=0))
        p_f1 = float(f1_score(y_arr, preds, pos_label=CLASS_PHISHING, zero_division=0))
        # FPR = Benign(1) falsely predicted as Phishing(0) / all Benign(1)
        cm = confusion_matrix(y_arr, preds, labels=[CLASS_PHISHING, CLASS_BENIGN])
        fp_benign = int(cm[1, 0])
        tn_benign = int(cm[1, 1])
        fpr = float(fp_benign / max(1, fp_benign + tn_benign))

        cand = {
            "threshold": float(tau),
            "phishing_f1": p_f1,
            "phishing_precision": p_prec,
            "phishing_recall": p_rec,
            "fpr": fpr,
        }
        if fpr <= max(0.15, max_fpr):
            if best_fallback is None or cand["phishing_f1"] > best_fallback["phishing_f1"]:
                best_fallback = cand

        if fpr <= max_fpr:
            if best_under_fpr is None or cand["phishing_f1"] > best_under_fpr["phishing_f1"]:
                best_under_fpr = cand

        if fpr <= max_fpr and p_rec >= min_phishing_recall:
            if best_feasible is None or cand["phishing_f1"] > best_feasible["phishing_f1"]:
                best_feasible = cand

    chosen = (
        best_feasible
        or best_under_fpr
        or best_fallback
        or {"threshold": 0.5, "phishing_f1": 0.0, "phishing_precision": 0.0, "phishing_recall": 0.0, "fpr": 1.0}
    )
    if len(y_phish_true) == 0:
        chosen["threshold"] = 0.5
    chosen["methodology"] = f"validation_grid_search_pos_class=0(min_recall>={min_phishing_recall}, max_fpr<={max_fpr})"
    return float(chosen["threshold"]), chosen


def calculate_metrics(y_true, y_pred, prob_phishing, logger: logging.Logger | None = None) -> dict:
    """
    Calculate explicit per-class metrics for BOTH Phishing (pos_label=0) and Benign (pos_label=1).
    Standard `Precision`, `Recall`, and `F1 Score` keys refer explicitly to Phishing (class 0).
    """
    y_arr = np.asarray(y_true, dtype=int)
    p_arr = np.asarray(y_pred, dtype=int)

    phishing_prec = float(precision_score(y_arr, p_arr, pos_label=CLASS_PHISHING, zero_division=0))
    phishing_rec = float(recall_score(y_arr, p_arr, pos_label=CLASS_PHISHING, zero_division=0))
    phishing_f1 = float(f1_score(y_arr, p_arr, pos_label=CLASS_PHISHING, zero_division=0))

    benign_prec = float(precision_score(y_arr, p_arr, pos_label=CLASS_BENIGN, zero_division=0))
    benign_rec = float(recall_score(y_arr, p_arr, pos_label=CLASS_BENIGN, zero_division=0))
    benign_f1 = float(f1_score(y_arr, p_arr, pos_label=CLASS_BENIGN, zero_division=0))

    metrics: dict = {
        "Positive Class": "0 (Phishing / Malicious)",
        "Accuracy": float(accuracy_score(y_arr, p_arr)),
        "Phishing Precision": phishing_prec,
        "Phishing Recall": phishing_rec,
        "Phishing F1": phishing_f1,
        "Benign Precision": benign_prec,
        "Benign Recall": benign_rec,
        "Benign F1": benign_f1,
        "Macro F1": float(f1_score(y_arr, p_arr, average="macro", zero_division=0)),
        # Compatibility aliases explicitly bound to Phishing class (0)
        "Precision": phishing_prec,
        "Recall": phishing_rec,
        "F1 Score": phishing_f1,
    }

    if prob_phishing is not None:
        try:
            y_phish = (y_arr == CLASS_PHISHING).astype(int)
            p_phish = np.asarray(prob_phishing, dtype=float)
            metrics["ROC AUC"] = float(roc_auc_score(y_phish, p_phish))
            metrics["PR AUC"] = float(average_precision_score(y_phish, p_phish))
        except Exception as e:
            if logger:
                logger.warning(f"Could not calculate ROC/PR AUC: {e}")
            metrics["ROC AUC"] = float("nan")
            metrics["PR AUC"] = float("nan")
    else:
        metrics["ROC AUC"] = float("nan")
        metrics["PR AUC"] = float("nan")

    # Confusion matrix with explicit rows/cols [0 (Phishing), 1 (Benign)]
    cm = confusion_matrix(y_arr, p_arr, labels=[CLASS_PHISHING, CLASS_BENIGN])
    tp_phish = int(cm[0, 0])
    fn_phish = int(cm[0, 1])  # Phishing missed as Benign
    fp_benign = int(cm[1, 0])  # Benign falsely flagged as Phishing
    tn_benign = int(cm[1, 1])

    metrics["FPR"] = float(fp_benign / max(1, fp_benign + tn_benign))
    metrics["FNR"] = float(fn_phish / max(1, tp_phish + fn_phish))
    metrics["Confusion Matrix"] = {
        "labels": ["0=Phishing", "1=Benign"],
        "tp_phishing": tp_phish,
        "fn_phishing_as_benign": fn_phish,
        "fp_benign_as_phishing": fp_benign,
        "tn_benign": tn_benign,
        "matrix": [[tp_phish, fn_phish], [fp_benign, tn_benign]],
    }
    return metrics


def plot_confusion_matrix(y_true, y_pred, model_name, save_dir="reports"):
    os.makedirs(save_dir, exist_ok=True)
    cm = confusion_matrix(y_true, y_pred, labels=[CLASS_PHISHING, CLASS_BENIGN])
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Phishing (0)", "Benign (1)"],
        yticklabels=["Phishing (0)", "Benign (1)"],
    )
    plt.title(f"Confusion Matrix - {model_name}")
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    file_path = os.path.join(save_dir, f"{model_name.lower().replace(' ', '_')}_confusion_matrix.png")
    plt.savefig(file_path, dpi=150)
    plt.close()


def plot_roc_curve(y_true, prob_phishing, model_name, save_dir="reports"):
    if prob_phishing is None:
        return
    os.makedirs(save_dir, exist_ok=True)
    try:
        y_phish = (np.asarray(y_true, dtype=int) == CLASS_PHISHING).astype(int)
        fpr, tpr, _ = roc_curve(y_phish, np.asarray(prob_phishing, dtype=float))
        auc_val = roc_auc_score(y_phish, np.asarray(prob_phishing, dtype=float))
        plt.figure(figsize=(7, 5))
        plt.plot(fpr, tpr, color="darkorange", lw=2, label=f"Phishing ROC (AUC = {auc_val:.4f})")
        plt.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate (Benign -> Phishing)")
        plt.ylabel("True Positive Rate (Phishing Recall)")
        plt.title(f"ROC Curve (Positive = Phishing 0) - {model_name}")
        plt.legend(loc="lower right")
        plt.tight_layout()
        file_path = os.path.join(save_dir, f"{model_name.lower().replace(' ', '_')}_roc_curve.png")
        plt.savefig(file_path, dpi=150)
        plt.close()
    except Exception as e:
        print(f"Skipping ROC curve plot for {model_name} due to: {e}")


def plot_feature_importance(model, feature_names, model_name, save_dir="reports", top_n=20):
    os.makedirs(save_dir, exist_ok=True)
    importances = getattr(model, "feature_importances_", None)
    if importances is None and hasattr(model, "calibrated_classifiers_"):
        est = getattr(model.calibrated_classifiers_[0], "estimator", None)
        importances = getattr(est, "feature_importances_", None)
    if importances is None:
        return

    indices = np.argsort(importances)[::-1][:top_n]
    top_importances = np.asarray(importances)[indices]
    top_features = [feature_names[i] for i in indices]

    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_importances, y=top_features, hue=top_features, palette="viridis", legend=False)
    plt.title(f"Top {top_n} Feature Importances - {model_name}")
    plt.xlabel("Relative Importance Score")
    plt.ylabel("Features")
    plt.tight_layout()
    file_path = os.path.join(save_dir, f"{model_name.lower().replace(' ', '_')}_feature_importance.png")
    plt.savefig(file_path, dpi=150)
    plt.close()


def plot_correlation_heatmap(X, save_dir="reports", max_features=25):
    os.makedirs(save_dir, exist_ok=True)
    if X.shape[1] > max_features:
        variances = X.var()
        df_corr = X[variances.nlargest(max_features).index]
        title_suffix = f" (Top {max_features} High-Variance Features)"
    else:
        df_corr = X
        title_suffix = ""
    plt.figure(figsize=(12, 10))
    sns.heatmap(df_corr.corr(), annot=False, cmap="coolwarm", fmt=".2f", linewidths=0.5)
    plt.title(f"Correlation Heatmap{title_suffix}")
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, "correlation_heatmap.png"), dpi=150)
    plt.close()


def evaluate_model(model, X_eval, y_eval, model_name, logger, threshold: float = 0.5) -> dict:
    """
    Evaluate model explicitly for Phishing (0) vs Benign (1) using `model.classes_`
    and the provided decision threshold on P(Phishing).
    """
    logger.info(f"Evaluating model: {model_name} (threshold={threshold:.2f})...")
    prob_phish, _ = get_class_probabilities(model, X_eval)
    y_pred = predict_with_threshold(prob_phish, threshold=threshold)

    metrics = calculate_metrics(y_eval, y_pred, prob_phish, logger)
    metrics["Threshold"] = float(threshold)
    report_str = classification_report(y_eval, y_pred, labels=[CLASS_PHISHING, CLASS_BENIGN], target_names=["Phishing (0)", "Benign (1)"], zero_division=0)
    report_dict = classification_report(y_eval, y_pred, labels=[CLASS_PHISHING, CLASS_BENIGN], target_names=["Phishing (0)", "Benign (1)"], output_dict=True, zero_division=0)
    metrics["Classification Report"] = report_dict

    logger.info(f"----- {model_name} Performance (Positive=Phishing 0) -----")
    for key in ("Accuracy", "Phishing Precision", "Phishing Recall", "Phishing F1", "Benign Precision", "Benign Recall", "Benign F1", "ROC AUC", "PR AUC", "FPR", "FNR"):
        val = metrics.get(key)
        if isinstance(val, (int, float)) and not np.isnan(val):
            logger.info(f"{key}: {val:.4f}")
    logger.info(f"Classification Report:\n{report_str}")

    try:
        plot_confusion_matrix(y_eval, y_pred, model_name)
        plot_roc_curve(y_eval, prob_phish, model_name)
        plot_feature_importance(model, X_eval.columns.tolist(), model_name)
    except Exception as e:
        logger.error(f"Plot generation error for {model_name}: {e}")

    return metrics
