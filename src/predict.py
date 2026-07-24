import os
import pandas as pd
import numpy as np
import logging
from src.utils import setup_logger, load_artifact

# Initialize logger
logger = logging.getLogger("FakeLoginDetection.Inference")
if not logger.handlers:
    logger = setup_logger()

def load_prediction_pipeline(models_dir="models"):
    """
    Loads all artifacts required for running inference.
    
    Args:
        models_dir (str): Folder containing models, encoders, and feature list.
        
    Returns:
        tuple: (model, feature_columns, TLD_encoder)
    """
    model_path = os.path.join(models_dir, "best_phishing_model.pkl")
    encoder_path = os.path.join(models_dir, "label_encoder.pkl")
    features_path = os.path.join(models_dir, "feature_columns.pkl")
    
    if not (os.path.exists(model_path) and os.path.exists(encoder_path) and os.path.exists(features_path)):
        raise FileNotFoundError(
            "Model artifacts are missing. Make sure to run 'src/train.py' first "
            "to generate the model, label encoder, and feature list."
        )
        
    # Load artifacts using our utils
    model = load_artifact(model_path, logger)
    encoders = load_artifact(encoder_path, logger)
    feature_columns = load_artifact(features_path, logger)
    
    return model, feature_columns, encoders

def predict_single_url(features_dict, model, feature_columns, encoders):
    """
    Runs prediction on a single URL's extracted features.
    
    Args:
        features_dict (dict): Dictionary mapping feature names to values.
        model: Trained classifier.
        feature_columns (list): List of feature names in the exact order.
        encoders (dict): Dictionary of fitted LabelEncoders.
        
    Returns:
        dict: Prediction results containing class and probability.
    """
    # Create a DataFrame from the feature dict
    df = pd.DataFrame([features_dict])
    
    # 1. Align features: Fill missing columns with default (0) and order them exactly as training
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0
            
    # Keep only features used in training in the correct order
    df_aligned = df[feature_columns].copy()
    
    # 2. Encode categorical columns (e.g. 'TLD') using the saved LabelEncoder
    for col, le in encoders.items():
        if col in df_aligned.columns:
            val = str(df_aligned[col].iloc[0])
            # If the value is new and wasn't in training, handle gracefully
            if val in le.classes_:
                df_aligned[col] = le.transform([val])
            else:
                # Assign a default unseen code or find a sensible fallback
                logger.warning(f"Unseen label '{val}' for categorical feature '{col}'. Assigning fallback encoding.")
                df_aligned[col] = 0 # Default to first class if unseen
                
    # 3. Predict class label
    prediction = model.predict(df_aligned)[0]
    
    # 4. Predict probability if model supports it
    probability = None
    if hasattr(model, "predict_proba"):
        probability = model.predict_proba(df_aligned)[0]
        
    result = {
        "class_label": int(prediction),
        "class_name": "Legitimate" if prediction == 1 else "Phishing / Fake Login",
        "phishing_probability": float(probability[0]) if probability is not None else None,
        "legitimate_probability": float(probability[1]) if probability is not None else None
    }
    
    return result

if __name__ == "__main__":
    logger.info("Running dummy prediction test...")
    
    # Try to load the pipeline. It requires train.py to have been run already.
    try:
        model, feature_columns, encoders = load_prediction_pipeline()
        
        # Example mock feature values extracted from a test website URL (e.g., https://secure-bank-login.xyz)
        # Note: In production, these features will be computed dynamically by your backend scraper/parser.
        sample_features = {
            "URLLength": 35,
            "DomainLength": 21,
            "IsDomainIP": 0,
            "TLD": "xyz", # Categorical value that will be encoded using the TLD LabelEncoder
            "URLSimilarityIndex": 35.5,
            "CharContinuationRate": 0.5,
            "TLDLegitimateProb": 0.002,
            "URLCharProb": 0.04,
            "TLDLength": 3,
            "NoOfSubDomain": 1,
            "HasObfuscation": 0,
            "NoOfObfuscatedChar": 0,
            "ObfuscationRatio": 0.0,
            "NoOfLettersInURL": 20,
            "LetterRatioInURL": 0.57,
            "NoOfDegitsInURL": 4,
            "DegitRatioInURL": 0.11,
            "NoOfEqualsInURL": 0,
            "NoOfQMarkInURL": 0,
            "NoOfAmpersandInURL": 0,
            "NoOfOtherSpecialCharsInURL": 2,
            "SpacialCharRatioInURL": 0.05,
            "IsHTTPS": 1,
            "LineOfCode": 45,
            "LargestLineLength": 200,
            "HasTitle": 1,
            "DomainTitleMatchScore": 10.0,
            "URLTitleMatchScore": 10.0,
            "HasFavicon": 0,
            "Robots": 0,
            "IsResponsive": 1,
            "NoOfURLRedirect": 0,
            "NoOfSelfRedirect": 0,
            "HasDescription": 0,
            "NoOfPopup": 0,
            "NoOfiFrame": 1, # Phishing indicator: contains iframe
            "HasExternalFormSubmit": 1, # Phishing indicator: submits form to external domain
            "HasSocialNet": 0,
            "HasSubmitButton": 1,
            "HasHiddenFields": 1,
            "HasPasswordField": 1, # Phishing indicator: contains password input fields
            "Bank": 1, # Phishing indicator: contains banking keywords
            "Pay": 0,
            "Crypto": 0,
            "HasCopyrightInfo": 0,
            "NoOfImage": 5,
            "NoOfCSS": 2,
            "NoOfJS": 3,
            "NoOfSelfRef": 2,
            "NoOfEmptyRef": 1,
            "NoOfExternalRef": 4
        }
        
        logger.info(f"Mock URL: 'https://secure-bank-login.xyz' (extracted TLD: '{sample_features['TLD']}')")
        
        # Run prediction
        result = predict_single_url(sample_features, model, feature_columns, encoders)
        
        logger.info("----- Prediction Result -----")
        logger.info(f"Class: {result['class_name']} ({result['class_label']})")
        if result['phishing_probability'] is not None:
            logger.info(f"Probability of being Phishing: {result['phishing_probability']:.2%}")
            logger.info(f"Probability of being Legitimate: {result['legitimate_probability']:.2%}")
            
    except FileNotFoundError as e:
        logger.warning(f"Skipping dummy prediction: {e}")
        logger.warning("Please train the model first by running: python src/train.py")
