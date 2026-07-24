# AI-Powered Fake Login Page Detection using Machine Learning

A complete, professional machine learning project for **B.Tech 3rd-Year AI & Data Science**. This project focuses on detecting phishing URLs and fake login pages by training classification models (Decision Tree, Random Forest, and XGBoost) on the **PhiUSIIL Phishing URL Dataset**. The trained best model is serialized for later integration into a Chrome Browser Extension via a web API backend (Flask/FastAPI).

---

## 📁 Project Structure

```text
"AI in Cyber security project"/
│
├── dataset/                               # Folder where dataset is placed (auto-managed)
│   └── PhiUSIIL_Phishing_URL_Dataset.csv
│
├── models/                                # Serialized model and preprocessors (auto-generated)
│   ├── best_phishing_model.pkl            # Trained Random Forest / best classifier
│   ├── label_encoder.pkl                  # Fitted LabelEncoder for categorical variables
│   └── feature_columns.pkl                # Ordered list of training features
│
├── notebooks/
│   └── Fake_Login_Detection_EDA.ipynb     # Jupyter Notebook for interactive EDA & training
│
├── reports/                               # Visualizations and performance tables (auto-generated)
│   ├── model_comparison_results.csv       # Metrics comparison table (CSV)
│   ├── correlation_heatmap.png            # Features correlation heatmap
│   ├── decision_tree_confusion_matrix.png
│   ├── random_forest_confusion_matrix.png
│   └── random_forest_roc_curve.png
│
├── logs/                                  # Log files capturing training outputs (auto-generated)
│   └── project.log
│
├── src/                                   # Project source code modules
│   ├── __init__.py                        # Packages marker
│   ├── utils.py                           # Directory helper, dual-logger, and joblib serializers
│   ├── preprocessing.py                   # Data loading, duplicate removal, null handling, encoding
│   ├── evaluate.py                        # Metrics calculator and plots generator (Heatmap, ROC, Importance)
│   ├── train.py                           # Orchestrator training pipeline comparing ML algorithms
│   └── predict.py                         # Single URL/mock features inference helper script
│
├── requirements.txt                       # Package dependencies
└── README.md                              # Project documentation
```

---

## 🚀 Getting Started & Installation

### Prerequisite
* Python 3.12+ installed on your computer.

### Step 1: Clone or Open the Project
Ensure the project structure matches the one shown above, with `PhiUSIIL_Phishing_URL_Dataset.csv` located at the root of the project workspace. 

### Step 2: Set up a Virtual Environment (Recommended)
Open your terminal (PowerShell or Command Prompt) in the project directory:
```bash
# Create a virtual environment named 'venv'
python -m venv venv

# Activate the virtual environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Windows (CMD):
.\venv\Scripts\activate.bat
```

### Step 3: Install Required Packages
Install all libraries (Pandas, Numpy, Scikit-Learn, Matplotlib, Seaborn, Joblib, and XGBoost) specified in the requirements file:
```bash
pip install -r requirements.txt
```

---

## 🏃 Running the Project

### 1. Training the Machine Learning Models (Main Pipeline)
Run the orchestrator script to automatically clean the dataset, train models, compare performance, and save the best-performing model:
```bash
python src/train.py
```
* **What happens behind the scenes:**
  * It detects `PhiUSIIL_Phishing_URL_Dataset.csv` at the root and moves it to `dataset/`.
  * It inspects the dataset for null values, removes duplicate records, and separates features.
  * It encodes the `TLD` column automatically using a `LabelEncoder` and saves it.
  * It generates a correlation matrix plot of the features in the `reports/` folder.
  * It splits the dataset into **80% training** and **20% testing** using stratified splits.
  * It trains a **Decision Tree**, **Random Forest**, and **XGBoost** (if installed).
  * It evaluates them on accuracy, precision, recall, f1-score, and ROC AUC, generating heatmaps/curves.
  * It compiles a comparison table, selects the best model (typically Random Forest), and saves it as `models/best_phishing_model.pkl`.

### 2. Interactive Analysis (Jupyter Notebook)
To perform step-by-step visualizations and exploratory analysis interactively:
```bash
jupyter notebook notebooks/Fake_Login_Detection_EDA.ipynb
```
*(Make sure to run `pip install jupyter` in your virtual environment first if not installed)*

### 3. Testing Single Inference
To test loading the trained model files and predicting a sample URL's status:
```bash
python src/predict.py
```

---

## 📊 Modules Explanation

### 1. Preprocessing (`src/preprocessing.py`)
* **Auto Target Detection:** Auto-detects the target column as `'label'` (or falls back to the last column).
* **Feature Pruning:** Drops `URL`, `Domain`, and `Title` since they are unique metadata and would cause target leakage or overfit.
* **Categorical Encoding:** Automatically finds non-numerical features (like `TLD` - top level domain) and encodes them using `LabelEncoder`.
* **Missing Value Imputation:** Fills numerical null values with column medians and categorical ones with modes to prevent training exceptions.

### 2. Evaluation (`src/evaluate.py`)
* Computes metrics: Accuracy, Precision, Recall, F1 Score, and Area Under the ROC Curve (ROC AUC).
* Generates **Confusion Matrix Heatmap**, **ROC Curve**, and **Feature Importance Bar Charts** using Matplotlib and Seaborn, and saves them to `reports/`.

### 3. Utilities (`src/utils.py`)
* Handles directory setup and dataset placement automatically.
* Implements standard logging writing to both console and `logs/project.log`.
* Encapsulates `joblib` loading and saving routines.

---

## 🔮 Future Integration Roadmap

This model is intended to protect users from entering passwords on fake login pages. The roadmap consists of three main components:

### 1. Chrome Extension Frontend
* **Popup (`popup.html` / `popup.js`):** A small UI that displays the security status (Safe vs. Suspicious) and probability score of the active tab.
* **Content Script (`content.js`):** Inspects page source code. It reads DOM elements (checks if there is a password input field or a login button) and counts tags, iframes, and external links to formulate the features list.
* **Background Script (`background.js`):** Intercepts tab changes or page load requests. It extracts the current URL (e.g., parses the top-level domain and length) and sends these raw page features as a JSON payload to our backend Web API.

### 2. FastAPI/Flask Backend
Since Chrome extensions cannot load heavy Python models directly in the browser, a Python API serves as the bridge:
* You host a FastAPI server containing a `/predict` POST endpoint.
* The API loads `best_phishing_model.pkl`, `label_encoder.pkl`, and `feature_columns.pkl` into memory upon startup.
* When the Chrome extension sends extracted page metrics, the API aligns, encodes, runs inference, and returns a JSON response:
  ```json
  {
    "url": "https://secure-bank-login.xyz",
    "is_phishing": true,
    "confidence": 0.985
  }
  ```

#### Example FastAPI Endpoint Draft:
```python
from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
import joblib

app = FastAPI()

# Load our saved artifacts
model = joblib.load("models/best_phishing_model.pkl")
encoders = joblib.load("models/label_encoder.pkl")
feature_names = joblib.load("models/feature_columns.pkl")

class URLFeatures(BaseModel):
    URLLength: int
    DomainLength: int
    IsDomainIP: int
    TLD: str
    IsHTTPS: int
    NoOfiFrame: int
    HasPasswordField: int
    # ... Include other features expected by the model

@app.post("/predict")
def predict_url(features: URLFeatures):
    data = pd.DataFrame([features.dict()])
    
    # Align columns and apply LabelEncoder to TLD
    data = data[feature_names]
    tld_encoder = encoders["TLD"]
    if data["TLD"].iloc[0] in tld_encoder.classes_:
        data["TLD"] = tld_encoder.transform(data["TLD"])
    else:
        data["TLD"] = 0 # Default fallback class
        
    pred = model.predict(data)[0]
    prob = model.predict_proba(data)[0][pred]
    
    return {
        "phishing": bool(pred == 0),
        "confidence": float(prob)
    }
```

### 3. Real-Time Phishing Detection
* **Heuristics & ML Hybrid:** To prevent overloading the server, the Chrome extension checks a local whitelist/blacklist database first (e.g. Google Safe Browsing API or popular sites list). If the domain is unknown and contains login forms, the background script extracts features and queries the ML model backend to render real-time protection shields to the user.
