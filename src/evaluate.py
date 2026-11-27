import os
import logging
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, 
    roc_auc_score, average_precision_score, confusion_matrix, classification_report, roc_curve
)

def calculate_metrics(y_true, y_pred, y_prob, logger):
    """
    Calculates accuracy, precision, recall, f1, roc auc, pr auc, FPR, and FNR.
    Note: class 1 = benign/legitimate, class 0 = risky/phishing.
    """
    metrics = {}
    metrics["Accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["Precision"] = float(precision_score(y_true, y_pred, zero_division=0))
    metrics["Recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    metrics["F1 Score"] = float(f1_score(y_true, y_pred, zero_division=0))
    
    if y_prob is not None:
        try:
            metrics["ROC AUC"] = float(roc_auc_score(y_true, y_prob))
            # Threat-class (class 0) PR-AUC
            y_threat = (np.asarray(y_true) == 0).astype(int)
            metrics["PR AUC"] = float(average_precision_score(y_threat, 1.0 - np.asarray(y_prob)))
        except Exception as e:
            logger.warning(f"Could not calculate ROC/PR AUC: {e}")
            metrics["ROC AUC"] = np.nan
            metrics["PR AUC"] = np.nan
    else:
        metrics["ROC AUC"] = np.nan
        metrics["PR AUC"] = np.nan

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    # Threat detection viewpoint: threat=0, benign=1
    # False positive = benign(1) misclassified as threat(0) -> fn / (fn + tp)
    # False negative = threat(0) misclassified as benign(1) -> fp / (tn + fp)
    metrics["FPR"] = float(fn / max(1, fn + tp))
    metrics["FNR"] = float(fp / max(1, tn + fp))
    return metrics

def plot_confusion_matrix(y_true, y_pred, model_name, save_dir="reports"):
    """
    Generates and saves a confusion matrix heatmap.
    """
    os.makedirs(save_dir, exist_ok=True)
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", 
                xticklabels=["Phishing (0)", "Legitimate (1)"],
                yticklabels=["Phishing (0)", "Legitimate (1)"])
    plt.title(f"Confusion Matrix - {model_name}")
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    
    file_path = os.path.join(save_dir, f"{model_name.lower().replace(' ', '_')}_confusion_matrix.png")
    plt.savefig(file_path, dpi=150)
    plt.close()

def plot_roc_curve(y_true, y_prob, model_name, save_dir="reports"):
    """
    Generates and saves an ROC Curve plot.
    """
    if y_prob is None:
        return
        
    os.makedirs(save_dir, exist_ok=True)
    
    try:
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        auc_val = roc_auc_score(y_true, y_prob)
        
        plt.figure(figsize=(7, 5))
        plt.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (area = {auc_val:.4f})")
        plt.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title(f"Receiver Operating Characteristic (ROC) - {model_name}")
        plt.legend(loc="lower right")
        plt.tight_layout()
        
        file_path = os.path.join(save_dir, f"{model_name.lower().replace(' ', '_')}_roc_curve.png")
        plt.savefig(file_path, dpi=150)
        plt.close()
    except Exception as e:
        print(f"Skipping ROC curve plot for {model_name} due to: {e}")

def plot_feature_importance(model, feature_names, model_name, save_dir="reports", top_n=20):
    """
    Extracts, plots, and saves model feature importances.
    """
    os.makedirs(save_dir, exist_ok=True)
    
    # Extract feature importances if available
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    else:
        return # Model doesn't support feature importance
        
    indices = np.argsort(importances)[::-1]
    
    # Limit to top N
    top_indices = indices[:top_n]
    top_importances = importances[top_indices]
    top_features = [feature_names[i] for i in top_indices]
    
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
    """
    Plots correlation matrix heatmap of the feature set.
    """
    os.makedirs(save_dir, exist_ok=True)
    
    # If there are too many columns, select top N columns by variance to keep heatmap readable
    if X.shape[1] > max_features:
        variances = X.var()
        top_variance_cols = variances.nlargest(max_features).index
        df_corr = X[top_variance_cols]
        title_suffix = f" (Top {max_features} High-Variance Features)"
    else:
        df_corr = X
        title_suffix = ""
        
    corr_matrix = df_corr.corr()
    
    plt.figure(figsize=(12, 10))
    sns.heatmap(corr_matrix, annot=False, cmap="coolwarm", fmt=".2f", linewidths=0.5)
    plt.title(f"Correlation Heatmap{title_suffix}")
    plt.tight_layout()
    
    file_path = os.path.join(save_dir, "correlation_heatmap.png")
    plt.savefig(file_path, dpi=150)
    plt.close()

def evaluate_model(model, X_test, y_test, model_name, logger):
    """
    Full evaluation pipeline for a model. Prints metrics and reports, 
    and saves all performance plots.
    
    Args:
        model: Trained scikit-learn or XGBoost model.
        X_test (pd.DataFrame): Test features.
        y_test (pd.Series): Test target.
        model_name (str): Display name for the model.
        logger (logging.Logger): Logger instance.
        
    Returns:
        dict: Dictionary containing metric scores.
    """
    logger.info(f"Evaluating model: {model_name}...")
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Try to predict probabilities (useful for ROC AUC)
    y_prob = None
    if hasattr(model, "predict_proba"):
        try:
            # For binary classification, grab the probability of the positive class (class 1)
            y_prob = model.predict_proba(X_test)[:, 1]
        except Exception as e:
            logger.warning(f"Failed to get class probabilities for {model_name}: {e}")
            
    # Calculate metrics
    metrics = calculate_metrics(y_test, y_pred, y_prob, logger)
    
    # Log metrics
    logger.info(f"----- {model_name} Performance -----")
    for metric, score in metrics.items():
        logger.info(f"{metric}: {score:.4f}")
        
    # Classification Report
    report = classification_report(y_test, y_pred, target_names=["Phishing", "Legitimate"])
    logger.info(f"Classification Report:\n{report}")
    
    # Plotting
    try:
        plot_confusion_matrix(y_test, y_pred, model_name)
        plot_roc_curve(y_test, y_prob, model_name)
        plot_feature_importance(model, X_test.columns.tolist(), model_name)
        logger.info(f"Saved confusion matrix, ROC curve, and feature importances for {model_name} in 'reports/'")
    except Exception as e:
        logger.error(f"Error occurred while generating plots for {model_name}: {e}")
        
    return metrics
