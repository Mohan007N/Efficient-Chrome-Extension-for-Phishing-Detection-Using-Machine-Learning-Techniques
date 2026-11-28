import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.risk_engine import HybridRiskEngine
from src.dom_features import extract_dom_features_from_html


def test_http_alone_is_not_phishing():
    engine = HybridRiskEngine()
    html = "<html><head><title>Public Reference</title></head><body><p>Hello world</p></body></html>"
    dom = extract_dom_features_from_html("http://public-docs.example.org/guide", html)
    res = engine.assess(
        url="http://public-docs.example.org/guide",
        url_threat_prob=0.10,
        dom_threat_prob=0.10,
        dom_features=dom,
        has_dom_observation=True,
    )
    assert res["dimensions"]["connection_security"]["status"] == "INSECURE_HTTP"
    assert res["dimensions"]["connection_security"]["level"] == "MEDIUM"
    assert res["dimensions"]["phishing_risk"]["level"] == "LOW"
    assert res["overall_risk_level"] == "MEDIUM"


def test_ads_alone_are_not_malware():
    engine = HybridRiskEngine()
    html = """
    <html><head><title>News Daily</title>
      <script src="https://ads.example.net/banner.js"></script>
      <script src="https://metrics.example.net/m.js"></script>
    </head><body>
      <iframe src="https://ads.example.net/slot1" width="300" height="250"></iframe>
      <p>Daily tech news.</p>
    </body></html>
    """
    dom = extract_dom_features_from_html("https://newsdaily.example.com/tech", html)
    res = engine.assess(
        url="https://newsdaily.example.com/tech",
        url_threat_prob=0.05,
        dom_threat_prob=0.05,
        dom_features=dom,
        has_dom_observation=True,
    )
    assert res["dimensions"]["malware_risk"]["level"] == "LOW"
    assert res["overall_risk_level"] == "LOW"


def test_unknown_domain_without_dom_cannot_claim_safe():
    engine = HybridRiskEngine()
    res = engine.assess(
        url="https://unobserved-domain.example.net/",
        url_threat_prob=None,
        dom_threat_prob=None,
        has_dom_observation=False,
        is_whitelisted=False,
    )
    assert res["overall_risk_level"] == "UNKNOWN"
    assert "dom_behavior" in res["unavailable_signals"]


def test_verified_threat_intel_sets_critical():
    engine = HybridRiskEngine()
    res = engine.assess(
        url="https://bad-phish.example.xyz/login",
        url_threat_prob=0.88,
        intel_result={
            "registry_match": {
                "matched": True,
                "source": "openphish",
                "category": "phishing",
                "reason": "Listed in OpenPhish.",
                "risk_floor": 0.95,
            }
        },
        has_dom_observation=False,
    )
    assert res["overall_risk_level"] == "CRITICAL"
    assert res["dimensions"]["phishing_risk"]["level"] == "CRITICAL"


def test_local_network_returns_unverified_not_safe():
    engine = HybridRiskEngine()
    res = engine.assess(
        url="http://127.0.0.1:3000/dashboard",
        hostname="127.0.0.1",
        is_local=True,
        has_dom_observation=True,
    )
    assert res["overall_risk_level"] == "UNKNOWN"
    assert res["operational_status"] == "LOCAL_NETWORK_UNVERIFIED"
    assert res["connection_security"] == "LOCAL_NETWORK_UNVERIFIED"
    assert res["phishing_probability"] is None


def test_whitelist_never_overrides_malicious_dom_or_threat_intel():
    engine = HybridRiskEngine()
    phish_html = """
    <html><head><title>Google Account Security</title></head>
    <body><form method="post" action="https://cred-harvest.invalid/post">
    <input type="email" name="email"/><input type="password" name="pw"/>
    <button type="submit">Verify</button></form></body></html>
    """
    dom = extract_dom_features_from_html("https://google.com/compromised-page", phish_html)
    res = engine.assess(
        url="https://google.com/compromised-page",
        url_threat_prob=0.12,
        dom_threat_prob=0.91,
        dom_features=dom,
        is_whitelisted=True,
        has_dom_observation=True,
    )
    assert res["overall_risk_level"] in ("HIGH", "CRITICAL")
    assert res["dimensions"]["credential_risk"]["level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert res["dimensions"]["credential_risk"]["score"] >= 0.50


def test_invalid_certificate_flagged_separately_and_missing_model_returns_null_prob():
    engine = HybridRiskEngine()
    res = engine.assess(
        url="https://expired-cert.invalid/",
        url_threat_prob=None,
        dom_threat_prob=None,
        intel_result={"tls": {"ssl_error": True, "ssl_error_detail": "CERTIFICATE_VERIFY_FAILED"}},
        has_dom_observation=False,
    )
    assert res["phishing_probability"] is None
    assert res["connection_security"] == "INVALID_CERTIFICATE"
    assert res["dimensions"]["connection_security"]["level"] == "HIGH"
    assert res["overall_risk_level"] == "HIGH"
    assert res["heuristic_risk_index"] >= 65


def test_firewall_blocked_host_is_blocked_status_not_malware():
    engine = HybridRiskEngine()
    res = engine.assess(
        url="https://corporate-blocked.invalid/",
        url_threat_prob=None,
        dom_threat_prob=None,
        reachability={"dns_sinkholed": True, "connection_blocked": True},
        has_dom_observation=False,
    )
    assert res["operational_status"] == "Blocked"
    assert res["phishing_probability"] is None
    assert res["dimensions"]["malware_risk"]["level"] == "UNKNOWN"


