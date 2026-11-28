"""
backend/schemas.py — Pydantic v2 Request & Response Models for Website Safety API (v3.0)
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class DOMFeaturesPayload(BaseModel):
    """Structured DOM & HTML behaviour telemetry (never contains passwords, values, cookies, or tokens)."""

    num_password_fields: int = Field(default=0, ge=0)
    num_username_email_inputs: int = Field(default=0, ge=0)
    num_login_forms: int = Field(default=0, ge=0)
    has_external_form_action: int = Field(default=0, ge=0, le=1)
    num_cross_domain_forms: int = Field(default=0, ge=0)
    num_hidden_credential_inputs: int = Field(default=0, ge=0)
    suspicious_login_indicators: int = Field(default=0, ge=0)
    brand_domain_mismatch: int = Field(default=0, ge=0, le=1)

    total_forms: int = Field(default=0, ge=0)
    external_forms_count: int = Field(default=0, ge=0)
    has_post_form: int = Field(default=0, ge=0, le=1)
    num_sensitive_inputs: int = Field(default=0, ge=0)
    num_payment_inputs: int = Field(default=0, ge=0)
    has_suspicious_payment_dest: int = Field(default=0, ge=0, le=1)
    has_prepaid_without_cod: int = Field(default=0, ge=0, le=1)
    has_restrictive_refund_terms: int = Field(default=0, ge=0, le=1)

    num_iframes: int = Field(default=0, ge=0)
    num_hidden_iframes: int = Field(default=0, ge=0)
    num_external_scripts: int = Field(default=0, ge=0)
    popup_trigger_count: int = Field(default=0, ge=0)
    fake_download_button_count: int = Field(default=0, ge=0)
    suspicious_link_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    meta_refresh_redirects: int = Field(default=0, ge=0)
    js_redirect_indicators: int = Field(default=0, ge=0)
    misleading_button_count: int = Field(default=0, ge=0)
    external_link_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    notification_prompt_requested: int = Field(default=0, ge=0, le=1)

    inline_script_count: int = Field(default=0, ge=0)
    suspicious_inline_js_count: int = Field(default=0, ge=0)
    obfuscated_js_score: float = Field(default=0.0, ge=0.0, le=1.0)
    dynamic_dom_mutation_count: int = Field(default=0, ge=0)
    html_line_count: int = Field(default=0, ge=0)
    has_title: int = Field(default=0, ge=0, le=1)
    domain_title_match_score: float = Field(default=0.0, ge=0.0, le=100.0)
    has_copyright_notice: int = Field(default=0, ge=0, le=1)
    has_official_contact_cue: int = Field(default=0, ge=0, le=1)

    # Keep Optional so omitted DOM payload never asserts HTTPS=1 on HTTP pages
    is_https: Optional[int] = Field(default=None, ge=0, le=1)
    mixed_content_count: int = Field(default=0, ge=0)
    cross_origin_iframes_uninspected: int = Field(default=0, ge=0)
    unavailable_signals: list[str] = Field(default_factory=list)
    analysis_mode: Optional[str] = Field(default=None, max_length=64)
    dom_fingerprint: Optional[str] = Field(default=None, max_length=128)


class URLFeaturesRequest(BaseModel):
    """Chrome Extension /predict payload with legacy fields + structured dom_features."""

    url: str = Field(default="", max_length=2048)
    hostname: str = Field(default="", max_length=512)

    URLLength: int = Field(default=0, ge=0)
    DomainLength: int = Field(default=0, ge=0)
    IsDomainIP: int = Field(default=0, ge=0, le=1)
    TLD: str = Field(default="com", max_length=64)
    TLDLength: int = Field(default=3, ge=0)
    NoOfSubDomain: int = Field(default=0, ge=0)

    HasObfuscation: int = Field(default=0, ge=0, le=1)
    NoOfObfuscatedChar: int = Field(default=0, ge=0)
    ObfuscationRatio: float = Field(default=0.0, ge=0.0)
    NoOfLettersInURL: int = Field(default=0, ge=0)
    LetterRatioInURL: float = Field(default=0.0, ge=0.0)
    NoOfDegitsInURL: int = Field(default=0, ge=0)
    DegitRatioInURL: float = Field(default=0.0, ge=0.0)
    NoOfEqualsInURL: int = Field(default=0, ge=0)
    NoOfQMarkInURL: int = Field(default=0, ge=0)
    NoOfAmpersandInURL: int = Field(default=0, ge=0)
    NoOfOtherSpecialCharsInURL: int = Field(default=0, ge=0)
    SpacialCharRatioInURL: float = Field(default=0.0, ge=0.0)
    CharContinuationRate: float = Field(default=0.0, ge=0.0)

    IsHTTPS: Optional[int] = Field(default=None, ge=0, le=1)
    LineOfCode: int = Field(default=0, ge=0)
    LargestLineLength: int = Field(default=0, ge=0)
    HasTitle: int = Field(default=0, ge=0, le=1)
    DomainTitleMatchScore: float = Field(default=0.0, ge=0.0)
    URLTitleMatchScore: float = Field(default=0.0, ge=0.0)
    HasFavicon: int = Field(default=0, ge=0, le=1)
    Robots: int = Field(default=0, ge=0, le=1)
    IsResponsive: int = Field(default=0, ge=0, le=1)
    NoOfURLRedirect: int = Field(default=0, ge=0)
    NoOfSelfRedirect: int = Field(default=0, ge=0)
    HasDescription: int = Field(default=0, ge=0, le=1)
    NoOfPopup: int = Field(default=0, ge=0)
    NoOfiFrame: int = Field(default=0, ge=0)
    HasExternalFormSubmit: int = Field(default=0, ge=0, le=1)
    HasSocialNet: int = Field(default=0, ge=0, le=1)
    HasSubmitButton: int = Field(default=0, ge=0, le=1)
    HasHiddenFields: int = Field(default=0, ge=0, le=1)
    HasPasswordField: int = Field(default=0, ge=0, le=1)

    Bank: int = Field(default=0, ge=0, le=1)
    Pay: int = Field(default=0, ge=0, le=1)
    Crypto: int = Field(default=0, ge=0, le=1)
    HasCopyrightInfo: int = Field(default=0, ge=0, le=1)

    NoOfImage: int = Field(default=0, ge=0)
    NoOfCSS: int = Field(default=0, ge=0)
    NoOfJS: int = Field(default=0, ge=0)
    NoOfSelfRef: int = Field(default=0, ge=0)
    NoOfEmptyRef: int = Field(default=0, ge=0)
    NoOfExternalRef: int = Field(default=0, ge=0)

    dom_features: Optional[DOMFeaturesPayload] = None
    redirect_chain: list[str] = Field(default_factory=list)


class PredictionResponse(BaseModel):
    """
    Assessment response strictly separating calibrated ML phishing_probability (null if unavailable)
    from heuristic_risk_index and overall_risk_level.
    """

    is_phishing: bool
    phishing_probability: Optional[float] = None
    legitimate_probability: Optional[float] = None
    heuristic_risk_index: Optional[int] = None
    overall_risk_level: str = "UNKNOWN"
    prediction_label: str = "Unverified"
    confidence: float = 0.5
    operational_status: str = "Unknown"
    connection_security: str = "UNKNOWN"
    model_availability: dict[str, Any] = Field(default_factory=dict)
    verdict: str
    risk_level: str
    whitelisted: bool = False
    top_indicators: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)
    shap_attributions: list[dict[str, Any]] = Field(default_factory=list)
    assessment: Optional[dict[str, Any]] = None


class AnalyzeURLRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    fetch_live: bool = Field(default=False, description="Optionally perform SSRF-safe backend static HTML fetch")
    deep_scan: bool = Field(default=True, description="Include threat intel, RDAP, and TLS checks")


class AnalyzeDOMRequest(BaseModel):
    url: str = Field(default="", max_length=2048)
    html: Optional[str] = Field(default=None, max_length=1_500_000, description="Optional raw HTML to parse statically")
    dom_features: Optional[DOMFeaturesPayload] = None


class AnalyzeWebsiteRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    html: Optional[str] = Field(default=None, max_length=1_500_000)
    dom_features: Optional[DOMFeaturesPayload] = None
    redirect_chain: list[str] = Field(default_factory=list)
    fetch_live: bool = Field(default=False)
    deep_scan: bool = Field(default=True)


class WebsiteAssessmentResponse(BaseModel):
    url: str
    hostname: str
    overall_risk_level: str
    prediction_label: str = "Unverified"
    phishing_probability: Optional[float] = None
    heuristic_risk_index: Optional[int] = None
    confidence: float = 0.5
    operational_status: str = "Unknown"
    connection_security: str = "UNKNOWN"
    model_availability: dict[str, Any] = Field(default_factory=dict)
    analysis_mode: str = "url_only"
    url_model_threat_probability: Optional[float] = None
    dom_model_threat_probability: Optional[float] = None
    thresholds: dict[str, float] = Field(default_factory=dict)
    verdict: str
    whitelisted: bool = False
    dimensions: dict[str, Any] = Field(default_factory=dict)
    brand_impersonation: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)
    unavailable_signals: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    assessment_confidence_note: str = ""
    shap_attributions: list[dict[str, Any]] = Field(default_factory=list)
    tranco_rank: Optional[int] = None
    domain_age_days: Optional[int] = None
    registry_match: dict[str, Any] = Field(default_factory=dict)


class ExplainRequest(BaseModel):
    url: str = Field(default="", max_length=2048)
    hostname: Optional[str] = Field(default="", max_length=512)
    is_phishing: Optional[bool] = Field(default=True)
    risk_level: Optional[str] = Field(default="HIGH")
    phishing_probability: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    heuristic_risk_index: Optional[int] = Field(default=None, ge=0, le=100)
    features: Optional[dict[str, Any]] = Field(default_factory=dict)
    assessment: Optional[dict[str, Any]] = Field(default=None)
    groq_api_key: Optional[str] = Field(default=None)


class ExplainResponse(BaseModel):
    explanation: str
    prediction_label: str = "Unverified"
    summary: str = ""
    key_signals: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    top_indicators: list[str] = Field(default_factory=list)
    feature_attributions: list[dict[str, Any]] = Field(default_factory=list)
    source: str
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    url_model_loaded: bool
    dom_model_loaded: bool
    model_type: str
    feature_count: int
    threat_intel_loaded: bool
    degraded: bool = False
    registry_integrity_ok: bool = True
    model_errors: list[str] = Field(default_factory=list)


class VersionResponse(BaseModel):
    api_version: str
    url_model_version: str
    dom_model_version: str
    schema_version: str


class ModelInfoResponse(BaseModel):
    active_manifest: dict[str, Any] = Field(default_factory=dict)
    url_feature_count: int
    dom_feature_count: int
    threat_intel_status: dict[str, Any] = Field(default_factory=dict)
    model_availability: dict[str, Any] = Field(default_factory=dict)


class FeedbackRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    report_type: str = Field(..., pattern="^(false_positive|missed_suspicious|incorrect_risk|incorrect_phishing)$")
    reported_risk_level: Optional[str] = Field(default=None, max_length=32)
    expected_category: Optional[str] = Field(default=None, max_length=64)
    notes: Optional[str] = Field(default="", max_length=1000)


class FeedbackResponse(BaseModel):
    status: str
    report_id: str
    verification_status: str
    message: str
