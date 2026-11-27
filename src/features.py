"""
src/features.py — Shared Lexical, Brand-Impersonation & Commerce Risk Feature Engineering

Computes deterministic features identically during training (src/preprocessing.py)
and inference (backend/predictor.py) from URL/Domain metadata + the 46 base DOM/URL
features sent by the Chrome Extension. Keeping this logic in one module prevents
train/inference skew and avoids duplicating feature code.
"""

from __future__ import annotations

import re
import numpy as np
import pandas as pd


# Disposable / heavily abused TLDs across phishing & fake storefronts
SUSPICIOUS_COMMERCE_TLDS = {
    "xyz", "top", "work", "tk", "ml", "cf", "gq", "ga", "buzz", "cc",
    "rest", "fit", "surf", "casa", "icu", "click", "link", "party",
    "country", "stream", "gdn", "kim", "mom", "vip", "win", "cam",
    "shop", "store", "online", "site", "club", "cfd", "sbs", "live",
    "deals", "loan", "pro", "bid", "trade", "pw", "cyou", "monster",
}

# Commercial-lure, fake-support & clone keywords often embedded in unauthorized domains
SCAM_DOMAIN_KEYWORDS = (
    "deal", "deals", "offer", "offers", "discount", "sale", "mega",
    "bazaar", "bazar", "kart", "mart", "outlet", "verify", "secure",
    "support", "helpdesk", "refund", "claim", "reward", "prize",
    "bonus", "cashback", "recharge", "booking", "ticket", "tatkal",
    "track", "kyc", "update", "login", "signin", "auth", "wallet",
    "portal", "official", "service", "customercare", "care",
)

# High-value brands & their official root domains for impersonation detection.
# Keep tokens >= 5 chars (or unmistakable brand markers) to prevent substring false positives.
PROTECTED_BRANDS: dict[str, set[str]] = {
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.jp", "amazonaws.com"},
    "flipkart": {"flipkart.com"},
    "myntra": {"myntra.com"},
    "meesho": {"meesho.com"},
    "nykaa": {"nykaa.com"},
    "tatacliq": {"tatacliq.com"},
    "jiomart": {"jiomart.com"},
    "snapdeal": {"snapdeal.com"},
    "croma": {"croma.com"},
    "vijaysales": {"vijaysales.com"},
    "bigbasket": {"bigbasket.com"},
    "blinkit": {"blinkit.com"},
    "zepto": {"zeptonow.com", "zepto.com"},
    "swiggy": {"swiggy.com"},
    "zomato": {"zomato.com"},
    "makemytrip": {"makemytrip.com"},
    "goibibo": {"goibibo.com"},
    "cleartrip": {"cleartrip.com"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "bookmyshow": {"bookmyshow.com"},
    "redbus": {"redbus.in"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "razorpay": {"razorpay.com"},
    "googlepay": {"pay.google.com", "gpay.app"},
    "paypal": {"paypal.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "onlinesbi": {"onlinesbi.sbi", "sbi.co.in"},
    "delhivery": {"delhivery.com"},
    "bluedart": {"bluedart.com"},
    "indiapost": {"indiapost.gov.in"},
    "apple": {"apple.com", "icloud.com"},
    "samsung": {"samsung.com"},
    "netflix": {"netflix.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "telegram": {"telegram.org", "t.me"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "ebay": {"ebay.com"},
    "walmart": {"walmart.com"},
    "shopify": {"shopify.com", "myshopify.com"},
    "adidas": {"adidas.com", "adidas.co.in"},
    "nike": {"nike.com"},
    "vlebazaar": {"vlebazaar.in"},
}

TRUSTED_DOMAINS: set[str] = {
    # Search engines
    "google.com", "google.co.in", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    # Social & Messaging
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com",
    "discord.com", "twitch.tv", "telegram.org", "whatsapp.com",
    # Video & Entertainment
    "youtube.com", "youtu.be", "netflix.com", "primevideo.com", "hotstar.com",
    "disneyplus.com", "hulu.com", "vimeo.com", "dailymotion.com", "spotify.com",
    # Microsoft & Apple
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
    "azure.com", "microsoftonline.com", "xbox.com", "apple.com", "icloud.com",
    # Global & Indian Shopping / E-Commerce (verified major authorized platforms)
    "amazon.com", "amazon.in", "amazon.co.uk", "ebay.com", "flipkart.com",
    "walmart.com", "target.com", "alibaba.com", "aliexpress.com", "etsy.com",
    "ikea.com", "nike.com", "adidas.com", "adidas.co.in", "bestbuy.com",
    "myntra.com", "ajio.com", "nykaa.com", "meesho.com", "tatacliq.com",
    "croma.com", "reliancedigital.in", "vijaysales.com", "jiomart.com",
    "bigbasket.com", "blinkit.com", "zeptonow.com", "snapdeal.com",
    "decathlon.in", "lenskart.com", "firstcry.com", "pepperfry.com", "urbanladder.com",
    # Travel, Ticketing & Delivery Portals
    "irctc.co.in", "makemytrip.com", "goibibo.com", "cleartrip.com", "yatra.com",
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com",
    "bookmyshow.com", "redbus.in", "uber.com", "olacabs.com", "swiggy.com", "zomato.com",
    "delhivery.com", "bluedart.com", "indiapost.gov.in",
    # Banking & Payments
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "barclays.co.uk", "hsbc.com", "standardchartered.com",
    "paypal.com", "stripe.com", "razorpay.com", "paytm.com", "phonepe.com",
    "gpay.app", "npci.org.in", "incometax.gov.in", "uidai.gov.in", "mygov.in",
    # Tech / Cloud / Developer
    "github.com", "gitlab.com", "stackoverflow.com", "npmjs.com", "pypi.org",
    "cloudflare.com", "aws.amazon.com", "cloud.google.com", "python.org",
    "mozilla.org", "w3.org", "w3schools.com", "readthedocs.io", "scikit-learn.org",
    "pandas.pydata.org", "fastapi.tiangolo.com", "react.dev", "vitejs.dev",
    "tailwindcss.com", "huggingface.co", "groq.com", "docker.com",
    "kubernetes.io", "oracle.com", "ibm.com", "nvidia.com", "proton.me",
    "digitalocean.com", "heroku.com", "vercel.com", "netlify.com",
    "notion.so", "slack.com", "zoom.us", "dropbox.com", "box.com",
    "adobe.com", "salesforce.com", "atlassian.com", "shopify.com",
    "wordpress.com", "wix.com", "squarespace.com", "openai.com", "chatgpt.com", "anthropic.com",
    # Education & News
    "wikipedia.org", "wikimedia.org", "khanacademy.org", "coursera.org",
    "udemy.com", "edx.org", "medium.com", "arxiv.org",
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "ndtv.com", "thehindu.com", "indiatoday.in",
}

ENGINEERED_FEATURE_COLUMNS = [
    "DomainHyphenCount",
    "DomainDigitCount",
    "IsSuspiciousStoreTLD",
    "HasScamDomainKeyword",
    "BrandImpersonationScore",
    "PayWithoutTrustRatio",
    "EmptyToSelfLinkRatio",
    "ExternalToSelfLinkRatio",
    "AssetsPerLineRatio",
    "CommerceAuthRiskInteraction",
]


def extract_root_domain(hostname: str) -> str:
    """Extract normalized root domain (e.g. 'www.amazon.in' -> 'amazon.in')."""
    if not hostname:
        return ""
    host = hostname.lower().strip().rstrip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if not parts:
        return ""
    compound_second_level = {"co", "com", "net", "org", "gov", "edu", "ac", "in"}
    if len(parts) >= 3 and parts[-2] in compound_second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


_DELEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _build_typo_lookup() -> dict[str, str]:
    """Precompute O(1) lookup of all 1-edit typosquats for >=6-char protected brand names."""
    lookup: dict[str, str] = {}
    for brand in PROTECTED_BRANDS:
        if len(brand) < 6:
            continue
        variants: set[str] = set()
        for i in range(len(brand)):
            variants.add(brand[:i] + brand[i + 1:])  # deletion
            for ch in _ALPHABET:
                variants.add(brand[:i] + ch + brand[i + 1:])  # substitution
        for i in range(len(brand) + 1):
            for ch in _ALPHABET:
                variants.add(brand[:i] + ch + brand[i:])  # insertion
        variants.discard(brand)
        for v in variants:
            lookup.setdefault(v, brand)
    return lookup


_TYPO_LOOKUP = _build_typo_lookup()
_BRAND_KEYS = tuple(PROTECTED_BRANDS.keys())
_BRAND_SUBSTRING_RE = re.compile("|".join(re.escape(b) for b in _BRAND_KEYS))


def detect_brand_impersonation(hostname: str) -> tuple[float, str | None]:
    """
    Detect whether a hostname impersonates or typosquats a protected brand
    while NOT belonging to any of the brand's official root domains.

    Returns:
        (score in [0.0, 1.0], matched_brand or None)
    """
    if not hostname:
        return 0.0, None

    host = hostname.lower().strip().rstrip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    root = extract_root_domain(host)
    if not root:
        return 0.0, None

    deleet = host.translate(_DELEET_TABLE)
    labels = [p for p in re.split(r"[.\-_]+", host) if p]
    deleet_labels = [p for p in re.split(r"[.\-_]+", deleet) if p]

    # 1. Brand substring / token match inside non-official host
    if _BRAND_SUBSTRING_RE.search(host) or _BRAND_SUBSTRING_RE.search(deleet):
        best_score = 0.0
        matched_brand: str | None = None
        for brand in _BRAND_KEYS:
            official_roots = PROTECTED_BRANDS[brand]
            if root in official_roots or any(host.endswith("." + off) for off in official_roots):
                continue
            if brand in host or brand in deleet:
                score = 0.95 if (brand in labels or brand in deleet_labels) else 0.85
                if score > best_score:
                    best_score = score
                    matched_brand = brand
        if matched_brand is not None:
            return best_score, matched_brand

    # 2. O(1) single-edit typosquatting check on the primary domain label
    primary_label = root.split(".")[0]
    for lbl in (primary_label, primary_label.translate(_DELEET_TABLE)):
        typo_brand = _TYPO_LOOKUP.get(lbl)
        if typo_brand:
            official_roots = PROTECTED_BRANDS[typo_brand]
            if root not in official_roots and not any(host.endswith("." + off) for off in official_roots):
                return 0.90, typo_brand

    return 0.0, None


def _extract_host_series(df: pd.DataFrame) -> pd.Series:
    """Resolve lowercase domain/hostname strings from Domain, hostname, or URL columns."""
    if "Domain" in df.columns and df["Domain"].notna().any():
        hosts = df["Domain"].fillna("").astype(str)
    elif "hostname" in df.columns and df["hostname"].notna().any():
        hosts = df["hostname"].fillna("").astype(str)
    else:
        hosts = pd.Series("", index=df.index)

    if "URL" in df.columns or "url" in df.columns:
        url_col = "URL" if "URL" in df.columns else "url"
        missing_mask = hosts.str.strip() == ""
        if missing_mask.any():
            extracted = (
                df.loc[missing_mask, url_col]
                .fillna("")
                .astype(str)
                .str.extract(r"https?://([^/:?#]+)", expand=False)
                .fillna("")
            )
            hosts = hosts.where(~missing_mask, extracted)

    return hosts.str.lower().str.strip().str.rstrip(".")


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute the 10 shared engineered features from URL/Domain + base numeric features.
    Returns a DataFrame containing only ENGINEERED_FEATURE_COLUMNS aligned to df.index.
    """
    out = pd.DataFrame(index=df.index)
    hosts = _extract_host_series(df)

    # 1. Domain lexical signals
    out["DomainHyphenCount"] = hosts.str.count("-").astype(float)
    out["DomainDigitCount"] = hosts.str.count(r"\d").astype(float)

    if "TLD" in df.columns:
        tlds = df["TLD"].fillna("").astype(str).str.lower().str.strip().str.lstrip(".")
    else:
        tlds = hosts.str.split(".").str[-1].fillna("")
    out["IsSuspiciousStoreTLD"] = tlds.isin(SUSPICIOUS_COMMERCE_TLDS).astype(float)

    kw_pattern = r"(?:" + "|".join(re.escape(k) for k in SCAM_DOMAIN_KEYWORDS) + r")"
    out["HasScamDomainKeyword"] = hosts.str.contains(kw_pattern, regex=True, na=False).astype(float)

    # 2. Brand impersonation score (fast O(1) regex + typo-dict lookup per unique host)
    scores = np.zeros(len(df), dtype=float)
    if len(df) <= 50:
        for idx_pos, h in enumerate(hosts):
            scores[idx_pos] = detect_brand_impersonation(h)[0]
    else:
        unique_hosts = hosts.unique()
        host_score_map = {h: detect_brand_impersonation(h)[0] for h in unique_hosts}
        scores = hosts.map(host_score_map).fillna(0.0).to_numpy(dtype=float)
    out["BrandImpersonationScore"] = scores

    # 3. Structural commerce & trust-gap interaction features
    def _col(name: str, default: float = 0.0) -> pd.Series:
        if name in df.columns:
            return pd.to_numeric(df[name], errors="coerce").fillna(default).astype(float)
        return pd.Series(default, index=df.index, dtype=float)

    pay = _col("Pay")
    bank = _col("Bank")
    crypto = _col("Crypto")
    has_social = _col("HasSocialNet")
    has_copy = _col("HasCopyrightInfo")
    empty_ref = _col("NoOfEmptyRef")
    self_ref = _col("NoOfSelfRef")
    ext_ref = _col("NoOfExternalRef")
    title_match = _col("DomainTitleMatchScore")
    loc = _col("LineOfCode")
    n_img = _col("NoOfImage")
    n_css = _col("NoOfCSS")
    n_js = _col("NoOfJS")
    ext_sub = _col("HasExternalFormSubmit")
    hidden = _col("HasHiddenFields")
    is_https = _col("IsHTTPS", 1.0)

    trust_gap = (
        (has_social == 0).astype(float)
        + (has_copy == 0).astype(float)
        + (empty_ref >= 3).astype(float)
        + (self_ref <= 8).astype(float)
        + (title_match < 25.0).astype(float)
    )
    out["PayWithoutTrustRatio"] = (pay * (trust_gap / 5.0)).round(6)
    out["EmptyToSelfLinkRatio"] = np.minimum(50.0, empty_ref / (self_ref + 1.0)).round(6)
    out["ExternalToSelfLinkRatio"] = np.minimum(100.0, ext_ref / (self_ref + 1.0)).round(6)
    out["AssetsPerLineRatio"] = np.minimum(10.0, (n_img + n_css + n_js) / (loc + 1.0)).round(6)
    out["CommerceAuthRiskInteraction"] = (
        (pay + bank + crypto)
        * (1.0 + ext_sub + hidden + (1.0 - is_https) + (1.0 - has_copy))
    ).round(6)

    return out[ENGINEERED_FEATURE_COLUMNS]
