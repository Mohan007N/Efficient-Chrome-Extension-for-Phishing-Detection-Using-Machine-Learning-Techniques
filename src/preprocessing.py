import os
import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Ensure project root is in path so src.utils can be found
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils import save_artifact

def load_data(file_path, logger):
    """
    Loads the dataset from a CSV file.
    
    Args:
        file_path (str): Path to the CSV dataset.
        logger (logging.Logger): Logger instance.
        
    Returns:
        pd.DataFrame: Loaded DataFrame.
    """
    logger.info(f"Loading dataset from: {file_path}")
    try:
        df = pd.read_csv(file_path)
        logger.info(f"Dataset loaded successfully with shape: {df.shape}")
        return df
    except FileNotFoundError as e:
        logger.error(f"Dataset file not found: {file_path}. Error: {e}")
        raise e
    except Exception as e:
        logger.error(f"Error loading dataset: {e}")
        raise e

def inspect_data(df, logger):
    """
    Prints summary information about the dataset.
    
    Args:
        df (pd.DataFrame): The dataset.
        logger (logging.Logger): Logger instance.
    """
    logger.info("----- DATASET INSPECTION -----")
    logger.info(f"Shape of the dataset: {df.shape}")
    
    # Missing values check
    missing_counts = df.isnull().sum()
    total_missing = missing_counts.sum()
    logger.info(f"Total missing values in dataset: {total_missing}")
    if total_missing > 0:
        logger.info("Missing values per column:")
        for col, count in missing_counts[missing_counts > 0].items():
            logger.info(f"  - {col}: {count}")
            
    # Check for duplicates
    duplicate_count = df.duplicated().sum()
    logger.info(f"Total duplicate records: {duplicate_count}")
    
    # Target column analysis (assuming 'label' is target)
    if 'label' in df.columns:
        class_counts = df['label'].value_counts()
        logger.info("Class distribution of target column 'label':")
        for cls, count in class_counts.items():
            pct = (count / len(df)) * 100
            logger.info(f"  - Class {cls}: {count} ({pct:.2f}%)")
    
    logger.info("------------------------------")

def preprocess_pipeline(df, logger, target_col='label', drop_cols=None):
    """
    Performs data preprocessing:
    1. Removes duplicate records.
    2. Drops unnecessary high-cardinality/noisy columns (like URL, Domain, Title).
    3. Auto-detects and encodes categorical columns.
    4. Handles missing values.
    5. Saves the encoders.
    
    Args:
        df (pd.DataFrame): Raw DataFrame.
        logger (logging.Logger): Logger instance.
        target_col (str): Name of the target column.
        drop_cols (list): List of columns to drop.
        
    Returns:
        X (pd.DataFrame): Features.
        y (pd.Series): Target.
        encoders (dict): Dictionary of fitted LabelEncoders.
    """
    logger.info("Starting preprocessing pipeline...")
    
    # 1. Remove duplicate records
    initial_shape = df.shape
    df = df.drop_duplicates().reset_index(drop=True)
    duplicates_removed = initial_shape[0] - df.shape[0]
    if duplicates_removed > 0:
        logger.info(f"Removed {duplicates_removed} duplicate records. New shape: {df.shape}")
    else:
        logger.info("No duplicate records found.")
        
    # 2. Check if target column exists
    if target_col not in df.columns:
        # Auto-detect target: typically the last column or 'label'
        if 'label' in df.columns:
            target_col = 'label'
        else:
            target_col = df.columns[-1]
        logger.info(f"Target column auto-detected as: '{target_col}'")
    else:
        logger.info(f"Using configured target column: '{target_col}'")
        
    # 3. Default columns to drop if not specified
    # URL, Domain, and Title are unique/free-text metadata columns
    # URLSimilarityIndex, TLDLegitimateProb, URLCharProb are pre-computed similarity/probability
    # features that were derived using knowledge of the label (effectively encoding the answer).
    # Including them causes artificially perfect accuracy on any model.
    # Removing them gives a realistic and honest evaluation of ML feature power.
    if drop_cols is None:
        drop_cols = [
            'URL', 'Domain', 'Title',           # Metadata / free-text
            'URLSimilarityIndex',                # Always 100 for legitimate = label leakage
            'TLDLegitimateProb',                 # Pre-computed probability from labeled data
            'URLCharProb',                       # Pre-computed probability from labeled data
            'Robots',                            # Hardcoded to 0 in browser extension -> train/inference skew
            'NoOfSelfRedirect',                  # Not observable via DOM content script -> train/inference skew
        ]
        
    cols_to_drop_present = [col for col in drop_cols if col in df.columns and col != target_col]
    if cols_to_drop_present:
        df = df.drop(columns=cols_to_drop_present)
        logger.info(f"Dropped non-predictive/noisy columns: {cols_to_drop_present}")
        
    # Separate features and target
    X = df.drop(columns=[target_col])
    y = df[target_col]
    
    # 4. Handle categorical features
    encoders = {}
    
    # Auto-detect categorical columns
    categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
    logger.info(f"Detected categorical columns to encode: {categorical_cols}")
    
    for col in categorical_cols:
        logger.info(f"Encoding categorical column: '{col}' using LabelEncoder")
        # Handle missing values in categorical columns before encoding
        if X[col].isnull().any():
            mode_val = X[col].mode()[0]
            X[col] = X[col].fillna(mode_val)
            logger.info(f"Filled missing values in categorical column '{col}' with mode: '{mode_val}'")
            
        # Initialize and fit LabelEncoder
        le = LabelEncoder()
        # Cast to string to avoid comparison errors during fit
        X[col] = X[col].astype(str)
        X[col] = le.fit_transform(X[col])
        encoders[col] = le
        
    # 5. Handle missing values in numerical columns
    numerical_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    for col in numerical_cols:
        if X[col].isnull().any():
            median_val = X[col].median()
            X[col] = X[col].fillna(median_val)
            logger.info(f"Filled missing values in numerical column '{col}' with median: {median_val}")
            
    logger.info(f"Preprocessing completed. Final features count: {X.shape[1]}")
    return X, y, encoders

def split_and_prepare(X, y, logger, test_size=0.2, random_state=42):
    """
    Splits the preprocessed dataset into training and testing sets.
    Uses stratified split to preserve class distribution.
    
    Args:
        X (pd.DataFrame): Features.
        y (pd.Series): Target.
        logger (logging.Logger): Logger instance.
        test_size (float): Proportion of test set.
        random_state (int): Random state for reproducibility.
        
    Returns:
        tuple: X_train, X_test, y_train, y_test.
    """
    logger.info(f"Splitting dataset into train ({int((1-test_size)*100)}%) and test ({int(test_size*100)}%) sets...")
    
    # Stratified split is used for classification tasks
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=test_size, 
            random_state=random_state, 
            stratify=y
        )
        logger.info("Stratified train-test split successful.")
    except ValueError as e:
        # Fallback if target cannot be stratified (e.g. regression or single class)
        logger.warning(f"Stratification failed: {e}. Falling back to standard split.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=test_size, 
            random_state=random_state
        )
        
    logger.info(f"Train set shape: {X_train.shape}, Test set shape: {X_test.shape}")
    return X_train, X_test, y_train, y_test
