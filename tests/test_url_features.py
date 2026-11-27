import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.features import compute_brand_impersonation_details, extract_url_features


def test_normal_https_url():
    f = extract_url_features("https://www.amazon.in/dp/B001")
    assert f["is_https"] == 1
    assert f["is_ip_address"] == 0
    assert f["is_punycode_or_idn"] == 0
    assert f["has_unusual_port"] == 0
    assert f["is_url_shortener"] == 0
    assert f["brand_similarity_score"] == 0.0


def test_http_url_extracted_without_implying_impersonation():
    f = extract_url_features("http://archive-docs.example.org/manual.html")
    assert f["is_https"] == 0
    assert f["tld"] == "org"
    assert f["brand_similarity_score"] == 0.0


def test_ip_punycode_shortener_port_long_url():
    f_ip = extract_url_features("http://192.168.10.5:8443/login?next=%2Fadmin")
    assert f_ip["is_ip_address"] == 1
    assert f_ip["has_unusual_port"] == 1
    assert f_ip["has_url_obfuscation"] == 1

    f_puny = extract_url_features("https://xn--pple-43d.example.com/verify")
    assert f_puny["is_punycode_or_idn"] == 1

    f_short = extract_url_features("https://bit.ly/3xYzAbC")
    assert f_short["is_url_shortener"] == 1

    long_u = "https://login.example.xyz/" + ("x9K2mPq7Z4vB8nR1wT5yJ3cL6hF0dG" * 6) + "?session=1234567890"
    f_long = extract_url_features(long_u)
    assert f_long["url_length"] > 200
    assert f_long["is_suspicious_tld"] == 1
    assert f_long["url_entropy"] > 3.5


def test_brand_impersonation_detector():
    impersonated = compute_brand_impersonation_details("fl1pkart-mega-sale.shop")
    assert impersonated["brand_similarity_score"] >= 0.85
    assert impersonated["matched_brand"] == "flipkart"
    assert impersonated["has_homoglyph"] == 1

    official = compute_brand_impersonation_details("www.flipkart.com")
    assert official["brand_similarity_score"] == 0.0
    assert official["matched_brand"] is None


def test_www_canonicalization_invariance():
    from src.features import URL_FEATURE_COLUMNS
    with_www = extract_url_features("https://www.aurorabooks.org/catalog")
    without_www = extract_url_features("https://aurorabooks.org/catalog")
    for col in URL_FEATURE_COLUMNS:
        assert with_www[col] == without_www[col], f"Expected www invariance for {col}"

