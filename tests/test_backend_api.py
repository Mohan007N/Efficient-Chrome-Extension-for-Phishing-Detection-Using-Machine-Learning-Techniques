import json
import os
import sys
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.main as main_mod
from backend.main import app


def test_health_version_model_info_analytics():
    with TestClient(app) as client:
        h = client.get("/health")
        assert h.status_code == 200
        hb = h.json()
        assert hb["model_loaded"] is True
        assert hb["url_model_loaded"] is True
        assert hb["dom_model_loaded"] is True
        assert hb["registry_integrity_ok"] is True

        v = client.get("/version")
        assert v.status_code == 200
        assert v.json()["api_version"] == "3.0.0"
        assert v.json()["schema_version"] == "3.0.0"

        mi = client.get("/model-info")
        assert mi.status_code == 200
        mib = mi.json()
        assert mib["url_feature_count"] >= 20
        assert "feeds" in mib["threat_intel_status"]
        assert "integrity_ok" in mib["model_availability"]

        an = client.get("/analytics")
        assert an.status_code == 200
        assert "total_scans" in an.json()


def test_ssrf_protection_blocks_private_loopback_metadata_and_bad_schemes():
    with TestClient(app) as client:
        blocked_urls = [
            "http://127.0.0.1:8000/health",
            "http://localhost:8000/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/admin",
            "file:///etc/passwd",
            "ftp://example.com/file",
            "http://user:pass@example.com/",
        ]
        for bad_url in blocked_urls:
            resp = client.post("/analyze-url", json={"url": bad_url, "fetch_live": False, "deep_scan": False})
            assert resp.status_code == 400, f"Expected SSRF block for {bad_url}, got {resp.status_code}"


def test_malformed_json_returns_clean_422():
    with TestClient(app) as client:
        bad = client.post("/predict", content="{not valid json", headers={"Content-Type": "application/json"})
        assert bad.status_code == 422
        assert "traceback" not in bad.text.lower()


def test_predict_local_network_unverified_and_separated_scores():
    with TestClient(app) as client:
        r_loc = client.post("/predict", json={
            "url": "http://127.0.0.1:5173/app",
            "hostname": "127.0.0.1",
            "IsHTTPS": 0,
        })
        assert r_loc.status_code == 200
        loc_b = r_loc.json()
        assert loc_b["risk_level"] == "UNKNOWN"
        assert loc_b["operational_status"] == "LOCAL_NETWORK_UNVERIFIED"
        assert loc_b["phishing_probability"] is None

        pred = client.post("/predict", json={
            "url": "https://example.com/docs",
            "hostname": "example.com",
            "IsHTTPS": 1,
            "LineOfCode": 120,
            "HasTitle": 1,
            "DomainTitleMatchScore": 100.0,
        })
        assert pred.status_code == 200
        body = pred.json()
        assert "assessment" in body
        assert "heuristic_risk_index" in body
        assert "model_availability" in body
        assert body["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")


def test_analyze_dom_and_website_with_synthetic_fixtures():
    with TestClient(app) as client:
        phish_html = """
        <html><head><title>Amazon Account Verify</title></head>
        <body><form method="post" action="https://credential-collector.invalid/steal">
        <input type="email" name="email"/><input type="password" name="pw"/>
        <button type="submit">Verify</button></form></body></html>
        """
        r = client.post("/analyze-website", json={
            "url": "https://amaz0n-verify-account.invalid/login",
            "html": phish_html,
            "fetch_live": False,
            "deep_scan": False,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["overall_risk_level"] in ("HIGH", "CRITICAL")
        assert data["dimensions"]["credential_risk"]["level"] in ("HIGH", "CRITICAL")
        assert data["analysis_mode"] == "static_html"

        safe_html = """<!doctype html>
        <html lang="en">
        <head><meta charset="utf-8"><title>Aurora Goods Official Store</title></head>
        <body>
          <header><nav><a href="/">Home</a><a href="/about">About</a><a href="/contact">Contact</a></nav></header>
          <main>
            <h1>Welcome to Aurora Goods</h1>
            <p>Independent neighborhood retailer serving books and stationery since 2018.</p>
            <p>Customer support: support@auroragoods.invalid</p>
          </main>
          <footer><p>&copy; 2026 Aurora Goods. All rights reserved.</p></footer>
        </body>
        </html>"""
        r_safe = client.post("/analyze-dom", json={
            "url": "https://auroragoods.invalid/",
            "html": safe_html,
        })
        assert r_safe.status_code == 200
        assert r_safe.json()["overall_risk_level"] in ("LOW", "MEDIUM")


def test_explain_and_feedback_endpoints():
    with TestClient(app) as client:
        exp = client.post("/explain", json={
            "url": "https://example.com/docs",
            "hostname": "example.com",
            "is_phishing": False,
            "risk_level": "LOW",
            "phishing_probability": 0.05,
            "heuristic_risk_index": 5,
            "features": {"IsHTTPS": 1},
        })
        assert exp.status_code == 200
        assert len(exp.json()["explanation"]) > 10

        fb = client.post("/feedback", json={
            "url": "https://example.com/docs",
            "report_type": "false_positive",
            "notes": "Automated test feedback",
        })
        assert fb.status_code == 200
        assert fb.json()["verification_status"] == "pending_human_review"


def test_http_without_dom_scan_endpoints_auth_chunked_limit_and_feedback_redaction(monkeypatch, tmp_path):
    fb_path = tmp_path / "feedback.jsonl"
    monkeypatch.setattr(main_mod, "FEEDBACK_FILE", str(fb_path))

    with TestClient(app) as client:
        # http:// URL without DOM payload must preserve INSECURE_HTTP and mark dom_behavior unavailable
        r_http = client.post("/analyze-url", json={
            "url": "http://plain-http-fixture.invalid/login",
            "fetch_live": False,
            "deep_scan": False,
        })
        assert r_http.status_code == 200
        b_http = r_http.json()
        assert b_http["connection_security"] == "INSECURE_HTTP"
        assert b_http["analysis_mode"] == "url_only"
        assert "dom_behavior" in b_http["unavailable_signals"]
        assert "thresholds" in b_http

        # Empty dom_features={} via /predict does not count as valid DOM observation
        r_empty_dom = client.post("/predict", json={
            "url": "https://empty-dom-api.invalid/page",
            "hostname": "empty-dom-api.invalid",
            "dom_features": {},
        })
        assert r_empty_dom.status_code == 200
        assert r_empty_dom.json()["assessment"]["analysis_mode"] == "url_only"

        # /scan GET and POST work cleanly without Playwright
        s_post = client.post("/scan", json={"url": "https://example.com/", "fetch_live": False, "deep_scan": False})
        s_get = client.get("/scan", params={"url": "https://example.com/", "fetch_live": False, "deep_scan": False})
        assert s_post.status_code == 200 and s_get.status_code == 200

        # /feedback redacts sensitive query string values before persisting
        fb = client.post("/feedback", json={
            "url": "https://example.com/reset?token=super_secret_token&otp=123456",
            "report_type": "missed_suspicious",
            "notes": "Redaction check",
        })
        assert fb.status_code == 200
        written = [json.loads(line) for line in fb_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert "super_secret_token" not in written[-1]["url"]
        assert "123456" not in written[-1]["url"]
        assert "token=REDACTED" in written[-1]["url"]

        # Chunked streaming payload > 2 MB (no Content-Length header) is blocked with 413
        oversized = client.post("/predict", content=(b"a" * 700_000 for _ in range(4)))
        assert oversized.status_code == 413

        # Optional WEBSHIELD_API_KEY gates prediction endpoints while keeping /health & /version public
        monkeypatch.setenv("WEBSHIELD_API_KEY", "test-api-secret")
        assert client.get("/health").status_code == 200
        assert client.get("/version").status_code == 200
        assert client.post("/analyze-url", json={"url": "https://example.com/", "fetch_live": False, "deep_scan": False}).status_code == 401
        assert client.post(
            "/analyze-url",
            json={"url": "https://example.com/", "fetch_live": False, "deep_scan": False},
            headers={"X-API-Key": "test-api-secret"},
        ).status_code == 200

        # Structured XAI prediction_label + SHAP attributions on /analyze-website and /explain
        monkeypatch.delenv("WEBSHIELD_API_KEY", raising=False)
        safe_res = client.post("/analyze-website", json={
            "url": "https://example.com/",
            "html": "<html><head><title>Example Domain</title></head><body><p>Official example documentation.</p></body></html>",
            "fetch_live": False,
            "deep_scan": False,
        })
        assert safe_res.status_code == 200
        sb = safe_res.json()
        assert sb["prediction_label"] in ("Real (Legitimate)", "Caution (Suspicious)", "Unverified")
        assert isinstance(sb["shap_attributions"], list) and len(sb["shap_attributions"]) >= 1
        assert "label" in sb["shap_attributions"][0]

        exp_res = client.post("/explain", json={
            "url": "https://example.com/",
            "hostname": "example.com",
            "is_phishing": False,
            "risk_level": "LOW",
            "phishing_probability": 0.04,
            "heuristic_risk_index": 5,
            "features": {"IsHTTPS": 1},
        })
        assert exp_res.status_code == 200
        eb = exp_res.json()
        assert eb["prediction_label"] == "Real (Legitimate)"
        assert len(eb["summary"]) > 10
        assert isinstance(eb["key_signals"], list)
        assert len(eb["recommended_action"]) > 5

        # Official Amazon deep product/auth URL over HTTPS with clean DOM must NOT be flagged Fake/Phishing
        amz_res = client.post("/analyze-website", json={
            "url": "https://www.amazon.in/dp/B0CHWRXH8B/ref=sr_1_1?crid=123&keywords=phone&sprefix=phone%2Caps%2C200",
            "dom_features": {
                "is_https": 1,
                "html_line_count": 400,
                "has_title": 1,
                "domain_title_match_score": 80.0,
                "num_hidden_iframes": 1,
                "suspicious_inline_js_count": 2,
                "obfuscated_js_score": 0.55,
                "dynamic_dom_mutation_count": 2,
            },
            "fetch_live": False,
            "deep_scan": False,
        })
        assert amz_res.status_code == 200
        amz_b = amz_res.json()
        assert amz_b["overall_risk_level"] == "LOW"
        assert amz_b["prediction_label"] == "Real (Legitimate)"
