import os
import shutil
import logging
import joblib

def setup_logger(log_dir="logs", log_file="project.log"):
    """
    Sets up a dual-destination logger that outputs messages to both the console 
    and a log file.
    
    Args:
        log_dir (str): Directory where log files will be saved.
        log_file (str): Name of the log file.
        
    Returns:
        logging.Logger: Configured logger instance.
    """
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    log_path = os.path.join(log_dir, log_file)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger("FakeLoginDetection")
    logger.info("Logger initialized successfully.")
    return logger

def prepare_directories(logger):
    """
    Creates the necessary directories for the project structure and automatically
    moves the dataset from the root directory to the 'dataset' directory if found.
    
    Args:
        logger (logging.Logger): Logger instance for status updates.
    """
    # Define required folders
    directories = ["dataset", "models", "notebooks", "reports", "logs"]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}/")
            
    # Check if the dataset is in the root folder and move it to 'dataset/'
    root_dataset_path = "PhiUSIIL_Phishing_URL_Dataset.csv"
    target_dataset_path = os.path.join("dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
    
    if os.path.exists(root_dataset_path):
        logger.info(f"Found dataset at root: {root_dataset_path}. Moving to 'dataset/'...")
        try:
            shutil.move(root_dataset_path, target_dataset_path)
            logger.info(f"Successfully moved dataset to {target_dataset_path}")
        except Exception as e:
            logger.error(f"Error moving dataset: {e}")
    elif os.path.exists(target_dataset_path):
        logger.info(f"Dataset already present in target directory: {target_dataset_path}")
    else:
        logger.warning(
            f"Dataset not found at root or target path ({target_dataset_path}). "
            "Please ensure 'PhiUSIIL_Phishing_URL_Dataset.csv' is in the project directory."
        )

def save_artifact(obj, file_path, logger):
    """
    Serializes and saves a Python object (model, encoder, etc.) using joblib.
    
    Args:
        obj: The Python object to serialize.
        file_path (str): File path where the object should be saved.
        logger (logging.Logger): Logger instance for error and info logging.
    """
    try:
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        joblib.dump(obj, file_path)
        logger.info(f"Successfully saved artifact to: {file_path}")
    except Exception as e:
        logger.error(f"Failed to save artifact to {file_path}. Error: {e}")
        raise e

def load_artifact(file_path, logger):
    """
    Loads a serialized Python object using joblib.
    
    Args:
        file_path (str): File path of the serialized object.
        logger (logging.Logger): Logger instance.
        
    Returns:
        The deserialized Python object.
    """
    try:
        obj = joblib.load(file_path)
        logger.info(f"Successfully loaded artifact from: {file_path}")
        return obj
    except Exception as e:
        logger.error(f"Failed to load artifact from {file_path}. Error: {e}")
        raise e
