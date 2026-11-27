import os
import sys
import time
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier

# Ensure the project root is in sys.path so src imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our custom modules
from src.utils import setup_logger, prepare_directories, save_artifact
from src.preprocessing import load_data, inspect_data, preprocess_pipeline, split_and_prepare
from src.evaluate import evaluate_model, plot_correlation_heatmap

# Gracefully handle optional XGBoost package
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

def main():
    # 1. Initialize Logger
    logger = setup_logger()
    logger.info("Initializing phishing URL detection training pipeline...")
    
    # 2. Prepare Directories (Creates models/, dataset/, reports/, and moves dataset if at root)
    prepare_directories(logger)
    
    # Define dataset path
    dataset_path = os.path.join("dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
    
    if not os.path.exists(dataset_path):
        logger.error(
            f"Dataset not found at expected path: {dataset_path}. "
            "Please ensure the CSV file is placed inside the project root directory or dataset/ folder."
        )
        return
        
    # 3. Load Dataset
    df = load_data(dataset_path, logger)
    
    # 4. Inspect Data (Null checks, duplicate checks, class distributions)
    inspect_data(df, logger)
    
    # 5. Preprocess Dataset
    # Drops URL, Domain, Title (metadata) + URLSimilarityIndex, TLDLegitimateProb, URLCharProb
    # (pre-computed features that cause perfect accuracy / data leakage).
    X, y, encoders = preprocess_pipeline(df, logger, target_col='label')
    
    # Save the label encoders dictionary (e.g. {'TLD': label_encoder})
    save_artifact(encoders, os.path.join("models", "label_encoder.pkl"), logger)
    
    # Save the list of feature column names used during training (crucial for Chrome extension alignment)
    feature_columns = X.columns.tolist()
    save_artifact(feature_columns, os.path.join("models", "feature_columns.pkl"), logger)
    logger.info(f"Saved feature list containing {len(feature_columns)} features.")
    
    # 6. Generate and save the Correlation Heatmap
    logger.info("Generating and saving correlation heatmap for features...")
    plot_correlation_heatmap(X, save_dir="reports")
    
    # 7. Split into Train-Test (80% training, 20% testing, stratified split)
    X_train, X_test, y_train, y_test = split_and_prepare(X, y, logger, test_size=0.2, random_state=42)
    
    # 8. Define Models with constrained hyperparameters to prevent overfitting.
    #
    # Decision Tree — max_depth limits tree growth; min_samples_leaf forces leaf
    #   nodes to have at least 5 samples (avoids memorizing rare outliers).
    #
    # Random Forest — same constraints applied per tree; max_features='sqrt' means
    #   each split only sees sqrt(n_features) random features → increases diversity.
    #
    # XGBoost — max_depth=8 limits tree size; subsample & colsample_bytree add
    #   stochastic regularization to avoid overfitting noisy features.
    models_dict = {
        "Decision Tree": DecisionTreeClassifier(
            random_state=42,
            max_depth=18,         # Limit tree depth to prevent memorization
            min_samples_leaf=8,   # Each leaf must cover at least 8 samples
            min_samples_split=16  # A node must have 16 samples before splitting
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=120,
            random_state=42,
            n_jobs=-1,
            max_depth=20,
            min_samples_leaf=5,
            max_features='sqrt'
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=250,
            max_depth=8,
            learning_rate=0.08,
            min_samples_leaf=20,
            l2_regularization=2.0,
            random_state=42,
        ),
    }

    # If XGBoost is installed on the user's computer, we include it in the comparison
    if XGBOOST_AVAILABLE:
        logger.info("XGBoost library detected. Adding regularized XGBoost to training list.")
        models_dict["XGBoost"] = XGBClassifier(
            n_estimators=280,
            random_state=42,
            n_jobs=-1,
            eval_metric="logloss",
            max_depth=7,             # Balanced depth to prevent memorizing dataset quirks
            learning_rate=0.08,
            min_child_weight=5,      # Require stronger leaf support
            subsample=0.8,
            colsample_bytree=0.55,   # Spread tree splits across URL, security, and DOM features
            colsample_bylevel=0.65,
            reg_alpha=1.0,           # L1 regularization
            reg_lambda=3.0,          # L2 regularization
        )
    else:
        logger.warning("XGBoost library not found. Skipping XGBoost model training. (You can install it using pip install xgboost)")
        
    # 9. Train and Evaluate Models
    comparison_results = []
    trained_models = {}
    
    for model_name, model in models_dict.items():
        logger.info(f"--------------------------------------------------")
        logger.info(f"Training {model_name}...")
        
        start_time = time.time()
        # Train model
        model.fit(X_train, y_train)
        training_time = time.time() - start_time
        logger.info(f"{model_name} trained successfully in {training_time:.2f} seconds.")
        
        # Evaluate model (Calculates accuracy, precision, recall, f1, roc_auc, and plots reports)
        metrics = evaluate_model(model, X_test, y_test, model_name, logger)
        metrics["Model Name"] = model_name
        metrics["Training Time (s)"] = training_time
        
        comparison_results.append(metrics)
        trained_models[model_name] = model
        
    # 10. Model Comparison Table
    logger.info(f"--------------------------------------------------")
    logger.info("Comparing trained models:")
    comparison_df = pd.DataFrame(comparison_results)
    
    # Rearrange columns for neat display
    cols = ["Model Name", "Accuracy", "Precision", "Recall", "F1 Score", "ROC AUC", "Training Time (s)"]
    comparison_df = comparison_df[cols]
    
    # Display table in logs
    logger.info(f"\n{comparison_df.to_string(index=False)}")
    
    # Save comparison table to CSV
    comparison_df.to_csv(os.path.join("reports", "model_comparison_results.csv"), index=False)
    logger.info("Saved comparison results table to 'reports/model_comparison_results.csv'")
    
    # 11. Select Best Model (prioritize F1 Score, breaking ties by highest Precision to minimize false alarms)
    best_model_row = comparison_df.sort_values(by=["F1 Score", "Precision"], ascending=False).iloc[0]
    best_model_name = best_model_row["Model Name"]
    best_f1_score = best_model_row["F1 Score"]
    
    logger.info(f"*** BEST PERFORMING MODEL: {best_model_name} (F1 Score: {best_f1_score:.4f}) ***")
    
    # Save the best model
    best_model_obj = trained_models[best_model_name]
    best_model_path = os.path.join("models", "best_phishing_model.pkl")
    save_artifact(best_model_obj, best_model_path, logger)
    
    logger.info("Training pipeline execution finished successfully!")

if __name__ == "__main__":
    main()
