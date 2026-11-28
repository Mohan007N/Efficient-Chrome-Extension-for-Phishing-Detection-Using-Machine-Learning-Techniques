"""
src/predict.py — CLI Smoke Runner Using Unified v3.0 Multi-Model Backend Predictor
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.predictor import PhishingPredictor
from src.utils import setup_logger

logger = setup_logger()


if __name__ == "__main__":
    predictor = PhishingPredictor(
        models_dir=os.path.join(PROJECT_ROOT, "models"),
        dataset_dir=os.path.join(PROJECT_ROOT, "dataset"),
    )
    predictor.load()

    sample_url = "https://secure-bank-login.invalid/auth"
    sample_dom = {
        "num_password_fields": 1,
        "num_login_forms": 1,
        "has_external_form_action": 1,
        "num_iframes": 1,
        "is_https": 1,
        "has_title": 1,
        "domain_title_match_score": 10.0,
    }
    res = predictor.assess_website(url=sample_url, dom_features=sample_dom, deep_scan=False)
    logger.info(f"Sample URL: {sample_url}")
    logger.info(f"Verdict: {res['verdict']}")
    logger.info(
        f"Overall Risk: {res['overall_risk_level']} | Operational Status: {res['operational_status']} | "
        f"ML Phishing Prob: {res['phishing_probability']} | Heuristic Index: {res['heuristic_risk_index']}/100"
    )
    logger.info(f"Connection Security: {res['connection_security']} | Model Availability: {res['model_availability']}")
    logger.info(f"Dimensions: { {k: v['level'] for k, v in res['dimensions'].items()} }")
