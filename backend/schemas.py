"""
backend/schemas.py — Pydantic models for request/response validation.

These models define exactly what the Chrome Extension must send (URLFeaturesRequest)
and what the API will return (PredictionResponse).
"""

from pydantic import BaseModel, Field
from typing import Optional


class URLFeaturesRequest(BaseModel):
    """
    All 48 features extracted from a URL + its page content.
    The Chrome Extension content script computes these values
    and sends them as a JSON POST body.

    All fields have sensible defaults so the extension can send
    partial feature sets — missing features fall back to 0.
    """

    # ── Metadata (for whitelist check) ─────────────────────────────────────
    url: str = Field(default="", description="Full URL of the page being scanned")
    hostname: str = Field(default="", description="Hostname extracted from the URL")

    # ── URL Structure Features ──────────────────────────────────────────────
    URLLength: int = Field(default=0, description="Total character length of the URL")
    DomainLength: int = Field(default=0, description="Character length of the domain part")
    IsDomainIP: int = Field(default=0, description="1 if domain is an IP address, else 0")
    TLD: str = Field(default="com", description="Top-Level Domain (e.g. 'com', 'xyz', 'net')")
    TLDLength: int = Field(default=3, description="Length of the TLD string")
    NoOfSubDomain: int = Field(default=0, description="Number of subdomains in the URL")

    # ── URL Character Analysis ───────────────────────────────────────────────
    HasObfuscation: int = Field(default=0, description="1 if obfuscated characters are detected")
    NoOfObfuscatedChar: int = Field(default=0, description="Count of obfuscated characters")
    ObfuscationRatio: float = Field(default=0.0, description="Ratio of obfuscated chars to total")
    NoOfLettersInURL: int = Field(default=0, description="Count of alphabetic characters in URL")
    LetterRatioInURL: float = Field(default=0.0, description="Ratio of letters to URL length")
    NoOfDegitsInURL: int = Field(default=0, description="Count of digit characters in URL")
    DegitRatioInURL: float = Field(default=0.0, description="Ratio of digits to URL length")
    NoOfEqualsInURL: int = Field(default=0, description="Count of '=' characters in URL")
    NoOfQMarkInURL: int = Field(default=0, description="Count of '?' characters in URL")
    NoOfAmpersandInURL: int = Field(default=0, description="Count of '&' characters in URL")
    NoOfOtherSpecialCharsInURL: int = Field(default=0, description="Count of other special chars")
    SpacialCharRatioInURL: float = Field(default=0.0, description="Ratio of special chars to URL length")
    CharContinuationRate: float = Field(default=0.0, description="Rate of character continuation patterns")

    # ── Security & Protocol ──────────────────────────────────────────────────
    IsHTTPS: int = Field(default=0, description="1 if the URL uses HTTPS, else 0")

    # ── Page Content / DOM Features ──────────────────────────────────────────
    LineOfCode: int = Field(default=0, description="Total lines of HTML source code")
    LargestLineLength: int = Field(default=0, description="Length of the longest HTML line")
    HasTitle: int = Field(default=0, description="1 if the page has a <title> tag")
    DomainTitleMatchScore: float = Field(default=0.0, description="Score measuring domain-title similarity")
    URLTitleMatchScore: float = Field(default=0.0, description="Score measuring URL-title similarity")
    HasFavicon: int = Field(default=0, description="1 if the page has a favicon")
    Robots: int = Field(default=0, description="1 if robots.txt exists and is accessible")
    IsResponsive: int = Field(default=0, description="1 if the page has a responsive viewport meta tag")
    NoOfURLRedirect: int = Field(default=0, description="Number of URL redirects observed")
    NoOfSelfRedirect: int = Field(default=0, description="Number of self-referential redirects")
    HasDescription: int = Field(default=0, description="1 if the page has a meta description tag")
    NoOfPopup: int = Field(default=0, description="Number of popup calls (window.open) in scripts")
    NoOfiFrame: int = Field(default=0, description="Number of <iframe> tags on the page")
    HasExternalFormSubmit: int = Field(default=0, description="1 if a form submits to an external domain")
    HasSocialNet: int = Field(default=0, description="1 if social network links are present")
    HasSubmitButton: int = Field(default=0, description="1 if the page has a submit button")
    HasHiddenFields: int = Field(default=0, description="1 if the page has hidden input fields")
    HasPasswordField: int = Field(default=0, description="1 if the page has a password input field")

    # ── Content Keywords ─────────────────────────────────────────────────────
    Bank: int = Field(default=0, description="1 if banking-related keywords are present in page content")
    Pay: int = Field(default=0, description="1 if payment-related keywords are present")
    Crypto: int = Field(default=0, description="1 if crypto-related keywords are present")
    HasCopyrightInfo: int = Field(default=0, description="1 if the page contains copyright notice")

    # ── Resource Counts ──────────────────────────────────────────────────────
    NoOfImage: int = Field(default=0, description="Number of <img> tags on the page")
    NoOfCSS: int = Field(default=0, description="Number of external CSS stylesheet links")
    NoOfJS: int = Field(default=0, description="Number of external JavaScript includes")
    NoOfSelfRef: int = Field(default=0, description="Number of self-referential links (same domain)")
    NoOfEmptyRef: int = Field(default=0, description="Number of empty href='#' or href='' links")
    NoOfExternalRef: int = Field(default=0, description="Number of links pointing to external domains")

    class Config:
        json_schema_extra = {
            "example": {
                "URLLength": 35,
                "DomainLength": 21,
                "IsDomainIP": 0,
                "TLD": "xyz",
                "IsHTTPS": 0,
                "HasPasswordField": 1,
                "NoOfiFrame": 2,
                "HasExternalFormSubmit": 1,
                "Bank": 1,
                "HasHiddenFields": 1,
                "HasSubmitButton": 1,
            }
        }


class PredictionResponse(BaseModel):
    """Response returned by the /predict endpoint."""
    is_phishing: bool = Field(description="True if page is classified as phishing")
    phishing_probability: float = Field(description="Probability (0.0–1.0) of being phishing")
    legitimate_probability: float = Field(description="Probability (0.0–1.0) of being legitimate")
    verdict: str = Field(description="Human-readable verdict")
    risk_level: str = Field(description="Risk level: HIGH, MEDIUM, LOW, or SAFE")
    whitelisted: bool = Field(default=False, description="True if domain is in the trusted whitelist")


class HealthResponse(BaseModel):
    """Response returned by the /health endpoint."""
    status: str
    model_loaded: bool
    model_type: str
    feature_count: int
