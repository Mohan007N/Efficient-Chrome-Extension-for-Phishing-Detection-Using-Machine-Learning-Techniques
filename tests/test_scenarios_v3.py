"""Comprehensive 14-scenario verification suite + extension/diagnostics contracts for WebShield AI v3.0."""

import os
import shutil
import sys
import tempfile

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.intel import UnauthorizedIntelEngine
from backend.predictor import PhishingPredictor
from backend.risk_engine import HybridRiskEngine
from backend.security import SSRFBlockedError, validate_safe_url_and_resolve
from src.dom_features import DOM_FEATURE_COLUMNS, validate_dom_feature_schema
from src.features import (
    URL_FEATURE_COLUMNS,
    extract_url_features,
    is_hosted_user_content_subdomain,
    validate_url_feature_schema,
)


@pytest.fixture(scope="module")
def loaded_predictor():
    pred = PhishingPredictor(
        models_dir=os.path.join(PROJECT_ROOT, "models"),
        dataset_dir=os.path.join(PROJECT_ROOT, "dataset"),
    )
    pred.load()
    return pred


def _clean_https_dom(**overrides) -> dict:
    base = {
        "is_https": 1,
        "has_title": 1,
        "domain_title_match_score": 95.0,
        "has_copyright_notice": 1,
        "has_official_contact_cue": 1,
        "total_forms": 1,
        "external_forms_count": 0,
        "has_external_form_action": 0,
        "num_cross_domain_forms": 0,
        "num_password_fields": 0,
        "num_username_email_inputs": 0,
        "num_login_forms": 0,
        "num_hidden_credential_inputs": 0,
        "suspicious_login_indicators": 0,
        "brand_domain_mismatch": 0,
        "has_post_form": 1,
        "num_sensitive_inputs": 0,
        "num_payment_inputs": 0,
        "has_suspicious_payment_dest": 0,
        "has_prepaid_without_cod": 0,
        "has_restrictive_refund_terms": 0,
        "num_iframes": 0,
        "num_hidden_iframes": 0,
        "num_external_scripts": 4,
        "popup_trigger_count": 0,
        "fake_download_button_count": 0,
        "suspicious_link_ratio": 0.0,
        "meta_refresh_redirects": 0,
        "js_redirect_indicators": 0,
        "misleading_button_count": 0,
        "external_link_ratio": 0.05,
        "notification_prompt_requested": 0,
        "inline_script_count": 2,
        "suspicious_inline_js_count": 0,
        "obfuscated_js_score": 0.0,
        "dynamic_dom_mutation_count": 0,
        "html_line_count": 220,
    }
    base.update(overrides)
    return base


def test_scenario_01_official_amazon_product_page(loaded_predictor):
    url = "https://www.amazon.in/dp/B0CHWRXH8B/ref=sr_1_1?crid=12345ABC&keywords=wireless+headphones&qid=1700000000&sprefix=wire%2Caps%2C210&sr=8-1"
    res = loaded_predictor.assess_website(url=url, dom_features=_clean_https_dom(), deep_scan=False)
    assert res["overall_risk_level"] == "LOW"
    assert res["prediction_label"] == "Real (Legitimate)"
    diag = res.get("diagnostics") or {}
    expected_keys = {
        "url_model_probability",
        "dom_model_probability",
        "ensemble_probability",
        "threat_intelligence_result",
        "url_risk_score",
        "dom_risk_score",
        "brand_impersonation_score",
        "connection_security_result",
        "final_risk_score",
        "final_classification",
        "top_contributing_indicators",
        "missing_or_unavailable_evidence",
        "established_official",
        "url_query_tempered",
        "thresholds",
    }
    assert expected_keys.issubset(set(diag.keys()))
    assert diag["established_official"] is True


def test_scenario_02_legitimate_first_party_login(loaded_predictor):
    url = "https://accounts.google.com/signin/v2/identifier?hl=en"
    dom = _clean_https_dom(
        num_password_fields=1,
        num_username_email_inputs=1,
        num_login_forms=1,
        has_external_form_action=0,
        num_cross_domain_forms=0,
    )
    res = loaded_predictor.assess_website(url=url, dom_features=dom, deep_scan=False)
    assert res["overall_risk_level"] == "LOW"
    assert res["prediction_label"] == "Real (Legitimate)"


def test_scenario_03_legitimate_payment_checkout(loaded_predictor):
    url = "https://checkout.razorpay.com/v1/checkout.html"
    dom = _clean_https_dom(
        num_payment_inputs=2,
        num_sensitive_inputs=1,
        has_suspicious_payment_dest=0,
        has_external_form_action=0,
    )
    res = loaded_predictor.assess_website(url=url, dom_features=dom, deep_scan=False)
    assert res["overall_risk_level"] == "LOW"


def test_scenario_04_third_party_platform_evaluated_by_page_evidence(loaded_predictor):
    clean_medium = loaded_predictor.assess_website(
        url="https://medium.com/@securityengineer/oauth-hardening-guide",
        dom_features=_clean_https_dom(domain_title_match_score=80.0),
        deep_scan=False,
    )
    assert clean_medium["diagnostics"]["established_official"] is False
    assert clean_medium["overall_risk_level"] in ("LOW", "MEDIUM")

    malicious_hosted = HybridRiskEngine().assess(
        url="https://sites.google.com/view/sbi-kyc-update-now",
        hostname="sites.google.com",
        url_threat_prob=0.65,
        dom_threat_prob=0.88,
        url_features=extract_url_features("https://sites.google.com/view/sbi-kyc-update-now"),
        dom_features=_clean_https_dom(
            num_password_fields=1,
            num_login_forms=1,
            has_external_form_action=1,
            num_cross_domain_forms=1,
            suspicious_login_indicators=2,
            brand_domain_mismatch=1,
            domain_title_match_score=0.0,
        ),
        has_dom_observation=True,
        analysis_mode="url_and_dom",
        url_threshold=0.55,
        dom_threshold=0.65,
    )
    assert malicious_hosted["diagnostics"]["established_official"] is False
    assert malicious_hosted["overall_risk_level"] in ("HIGH", "CRITICAL")


def test_scenario_05_synthetic_lookalike_brand_impersonation(loaded_predictor):
    res = loaded_predictor.assess_website(
        url="https://amaz0n-login.example/signin",
        dom_features=_clean_https_dom(brand_domain_mismatch=1, domain_title_match_score=0.0),
        deep_scan=False,
    )
    assert res["diagnostics"]["brand_impersonation_score"] >= 0.7
    assert res["overall_risk_level"] in ("HIGH", "CRITICAL")
    assert res["prediction_label"] != "Real (Legitimate)"


def test_scenario_06_insecure_http_transport(loaded_predictor):
    res = loaded_predictor.assess_website(
        url="http://shop-checkout.example/cart",
        dom_features=_clean_https_dom(is_https=0),
        deep_scan=False,
    )
    assert res["connection_security"] == "INSECURE_HTTP"
    assert res["diagnostics"]["connection_security_result"]["status"] == "INSECURE_HTTP"


def test_scenario_07_empty_dom_not_auto_safe():
    res = HybridRiskEngine().assess(
        url="https://unknown-new-portal.example/login",
        hostname="unknown-new-portal.example",
        url_threat_prob=0.25,
        dom_threat_prob=None,
        url_features=extract_url_features("https://unknown-new-portal.example/login"),
        dom_features={},
        has_dom_observation=False,
        analysis_mode="url_only",
        url_threshold=0.55,
        dom_threshold=0.65,
    )
    diag = res["diagnostics"]
    assert diag["dom_model_probability"] is None
    assert len(diag["missing_or_unavailable_evidence"]) >= 1
    assert res["analysis_mode"] == "url_only"


def test_scenario_08_missing_threat_intel_unknown_not_auto_safe():
    res = HybridRiskEngine().assess(
        url="https://unverified-portal.example/auth",
        hostname="unverified-portal.example",
        url_threat_prob=0.62,
        dom_threat_prob=None,
        url_features=extract_url_features("https://unverified-portal.example/auth"),
        dom_features={},
        intel_result={"registry_match": {"matched": False}, "rdap": {}, "tls": {}},
        has_dom_observation=False,
        model_availability={"url_model": True, "dom_model": False, "threat_intel_degraded": True},
        analysis_mode="url_only",
        url_threshold=0.55,
        dom_threshold=0.65,
    )
    assert res["diagnostics"]["established_official"] is False
    assert res["overall_risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_scenario_09_known_malicious_threat_intel_critical():
    res = HybridRiskEngine().assess(
        url="https://malicious-feed-hit.example/signin",
        hostname="malicious-feed-hit.example",
        url_threat_prob=0.35,
        dom_threat_prob=None,
        url_features=extract_url_features("https://malicious-feed-hit.example/signin"),
        dom_features={},
        intel_result={
            "registry_match": {
                "matched": True,
                "source": "openphish",
                "category": "phishing",
                "reason": "URL matched verified OpenPhish feed.",
                "risk_floor": 0.95,
                "reliability": "high",
            }
        },
        has_dom_observation=False,
        analysis_mode="url_only",
        url_threshold=0.55,
        dom_threshold=0.65,
    )
    assert res["overall_risk_level"] == "CRITICAL"
    assert res["diagnostics"]["threat_intelligence_result"]["matched"] is True


def test_scenario_10_compromised_legitimate_domain_flagged():
    res = HybridRiskEngine().assess(
        url="https://www.amazon.in/gp/help/promo-verify",
        hostname="www.amazon.in",
        url_threat_prob=0.12,
        dom_threat_prob=0.92,
        url_features=extract_url_features("https://www.amazon.in/gp/help/promo-verify"),
        dom_features=_clean_https_dom(
            num_password_fields=1,
            num_login_forms=1,
            has_external_form_action=1,
            num_cross_domain_forms=1,
            num_hidden_iframes=2,
            suspicious_inline_js_count=4,
            obfuscated_js_score=4.5,
        ),
        has_dom_observation=True,
        analysis_mode="url_and_dom",
        url_threshold=0.55,
        dom_threshold=0.65,
        tranco_rank=15,
    )
    assert res["overall_risk_level"] in ("HIGH", "CRITICAL")
    assert res["prediction_label"] != "Real (Legitimate)"


def test_scenario_11_hosted_user_content_never_auto_trusted():
    engine = UnauthorizedIntelEngine()
    for host in (
        "sites.google.com",
        "evil-login.vercel.app",
        "phish-kit.github.io",
        "scam-store.netlify.app",
        "fake-blog.wordpress.com",
        "card-clone.wixsite.com",
    ):
        assert is_hosted_user_content_subdomain(host) is True
        assert engine.is_trusted(host) is False


def test_scenario_12_unknown_domain_cautious():
    res = HybridRiskEngine().assess(
        url="https://newly-registered-vendor.example/checkout",
        hostname="newly-registered-vendor.example",
        url_threat_prob=0.30,
        dom_threat_prob=0.25,
        url_features=extract_url_features("https://newly-registered-vendor.example/checkout"),
        dom_features=_clean_https_dom(domain_title_match_score=10.0),
        has_dom_observation=True,
        analysis_mode="url_and_dom",
        url_threshold=0.55,
        dom_threshold=0.65,
        tranco_rank=None,
    )
    assert res["diagnostics"]["established_official"] is False
    assert res["diagnostics"]["threat_intelligence_result"]["matched"] is False


def test_scenario_13_ssrf_and_redirect_risk_detection():
    for blocked_url in ("http://127.0.0.1:8000/admin", "http://169.254.169.254/latest/meta-data/"):
        with pytest.raises(SSRFBlockedError):
            validate_safe_url_and_resolve(blocked_url, resolve_dns=False)

    redirect_url = "https://portal.example/bounce?redirect=https://evil-harvest.example/login"
    res = HybridRiskEngine().assess(
        url=redirect_url,
        hostname="portal.example",
        url_threat_prob=0.52,
        dom_threat_prob=0.62,
        url_features=extract_url_features(redirect_url),
        dom_features=_clean_https_dom(meta_refresh_redirects=1, js_redirect_indicators=2),
        redirect_chain=[redirect_url, "https://evil-harvest.example/login"],
        has_dom_observation=True,
        analysis_mode="url_and_dom",
        url_threshold=0.55,
        dom_threshold=0.65,
    )
    assert res["heuristic_risk_index"] > 0
    assert res["overall_risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_scenario_14_feature_schema_mismatch_rejected(loaded_predictor):
    with pytest.raises(ValueError):
        validate_url_feature_schema(pd.DataFrame([{"url_length": 10}]), URL_FEATURE_COLUMNS)
    with pytest.raises(ValueError):
        validate_dom_feature_schema(pd.DataFrame([{"num_password_fields": 1}]), DOM_FEATURE_COLUMNS)

    tmp_dir = tempfile.mkdtemp(prefix="ws_schema_mismatch_")
    try:
        X = np.array([[0.0], [0.1], [1.0], [1.1]])
        y = np.array([0, 0, 1, 1])
        dummy = LogisticRegression().fit(X, y)
        joblib.dump(dummy, os.path.join(tmp_dir, "url_model.pkl"))
        joblib.dump(URL_FEATURE_COLUMNS[:-1], os.path.join(tmp_dir, "url_feature_columns.pkl"))

        pred = PhishingPredictor(models_dir=tmp_dir, dataset_dir=os.path.join(PROJECT_ROOT, "dataset"))
        pred.load()
        assert pred.url_model_ready() is False
        assert pred._url_model_status == "schema_mismatch"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extension_developer_diagnostics_panel_assets():
    with open(os.path.join(PROJECT_ROOT, "chrome_extension", "popup.html"), "r", encoding="utf-8") as f:
        html = f.read()
    with open(os.path.join(PROJECT_ROOT, "chrome_extension", "popup.js"), "r", encoding="utf-8") as f:
        js = f.read()
    for token in ("toggleDevDiagBtn", "devDiagBody", "devDiagGrid", "predictionLabelVal"):
        assert token in html
        assert token in js
    for diag_key in ("url_model_probability", "dom_model_probability", "ensemble_probability", "url_risk_score", "dom_risk_score"):
        assert diag_key in js
