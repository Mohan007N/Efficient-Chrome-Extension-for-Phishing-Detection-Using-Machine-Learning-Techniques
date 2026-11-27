"""
src/features.py — Separated URL & Brand Feature Engineering Pipeline

Provides:
1. URL normalization and URL-only feature extraction (`URL_FEATURE_COLUMNS`, `extract_url_features`,
   `extract_url_features_batch`) for Model 1 (URL Risk Classifier).
2. Brand impersonation & typosquatting analysis (`compute_brand_impersonation_details`,
   `detect_brand_impersonation`) for Model 3 (Brand Impersonation Detector).
3. Legacy compatibility helpers (`ENGINEERED_FEATURE_COLUMNS`, `engineer_features`) preserved
   for backward-compatible callers.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlparse, urlunparse

import numpy as np
import pandas as pd


SUSPICIOUS_COMMERCE_TLDS: set[str] = {
    "xyz", "top", "work", "tk", "ml", "cf", "gq", "ga", "buzz", "cc",
    "rest", "fit", "surf", "casa", "icu", "click", "link", "party",
    "country", "stream", "gdn", "kim", "mom", "vip", "win", "cam",
    "shop", "store", "online", "site", "club", "cfd", "sbs", "live",
    "deals", "loan", "pro", "bid", "trade", "pw", "cyou", "monster",
    "skin", "quest", "beauty",
}

URL_SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id",
    "zd.lc", "lnkd.in", "clk.im", "v.gd", "bc.vc", "shorte.st",
}

SCAM_DOMAIN_KEYWORDS: tuple[str, ...] = (
    "deal", "deals", "offer", "offers", "discount", "sale", "mega",
    "bazaar", "bazar", "kart", "mart", "outlet", "verify", "secure",
    "support", "helpdesk", "refund", "claim", "reward", "prize",
    "bonus", "cashback", "recharge", "booking", "ticket", "tatkal",
    "track", "kyc", "update", "login", "signin", "auth", "wallet",
    "portal", "official", "service", "customercare", "care", "account",
)

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
    "google": {"google.com", "google.co.in", "accounts.google.com", "drive.google.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
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
    "google.com", "google.co.in", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com",
    "discord.com", "twitch.tv", "telegram.org", "whatsapp.com",
    "youtube.com", "youtu.be", "netflix.com", "primevideo.com", "hotstar.com",
    "disneyplus.com", "hulu.com", "vimeo.com", "dailymotion.com", "spotify.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
    "azure.com", "microsoftonline.com", "xbox.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "ebay.com", "flipkart.com",
    "walmart.com", "target.com", "alibaba.com", "aliexpress.com", "etsy.com",
    "ikea.com", "nike.com", "adidas.com", "adidas.co.in", "bestbuy.com",
    "myntra.com", "ajio.com", "nykaa.com", "meesho.com", "tatacliq.com",
    "croma.com", "reliancedigital.in", "vijaysales.com", "jiomart.com",
    "bigbasket.com", "blinkit.com", "zeptonow.com", "snapdeal.com",
    "decathlon.in", "lenskart.com", "firstcry.com", "pepperfry.com", "urbanladder.com",
    "irctc.co.in", "makemytrip.com", "goibibo.com", "cleartrip.com", "yatra.com",
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com",
    "bookmyshow.com", "redbus.in", "uber.com", "olacabs.com", "swiggy.com", "zomato.com",
    "delhivery.com", "bluedart.com", "indiapost.gov.in",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "barclays.co.uk", "hsbc.com", "standardchartered.com",
    "paypal.com", "stripe.com", "razorpay.com", "paytm.com", "phonepe.com",
    "gpay.app", "npci.org.in", "incometax.gov.in", "uidai.gov.in", "mygov.in",
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
    "wikipedia.org", "wikimedia.org", "khanacademy.org", "coursera.org",
    "udemy.com", "edx.org", "medium.com", "arxiv.org",
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "ndtv.com", "thehindu.com", "indiatoday.in",
}

# Pure URL-only feature schema for Model 1 (strictly decoupled from DOM)
URL_FEATURE_COLUMNS: list[str] = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens_domain",
    "num_digits_url",
    "num_digits_domain",
    "num_special_chars",
    "is_ip_address",
    "is_punycode_or_idn",
    "has_unusual_port",
    "is_url_shortener",
    "has_url_obfuscation",
    "url_entropy",
    "domain_entropy",
    "tld_length",
    "is_suspicious_tld",
    "suspicious_keyword_count",
    "is_https",
    "brand_similarity_score",
    "typosquat_edit_distance",
    "char_continuation_rate",
    "letter_ratio",
    "digit_ratio",
    "tld",
]

# Legacy engineered columns retained for compatibility
ENGINEERED_FEATURE_COLUMNS: list[str] = [
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

_DELEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in SCAM_DOMAIN_KEYWORDS), re.I)


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
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        return host
    compound_second_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
    if len(parts) >= 3 and parts[-2] in compound_second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def normalize_url(url: str) -> str:
    """Canonicalize URL (lowercase scheme/host, strip fragment and default ports)."""
    raw = (url or "").strip()
    if not raw:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _build_typo_lookup() -> dict[str, str]:
    """Precompute O(1) lookup of 1-edit typosquats for >=6-char protected brand names."""
    lookup: dict[str, str] = {}
    for brand in PROTECTED_BRANDS:
        if len(brand) < 6:
            continue
        variants: set[str] = set()
        for i in range(len(brand)):
            variants.add(brand[:i] + brand[i + 1:])
            for ch in _ALPHABET:
                variants.add(brand[:i] + ch + brand[i + 1:])
        for i in range(len(brand) + 1):
            for ch in _ALPHABET:
                variants.add(brand[:i] + ch + brand[i:])
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

    primary_label = root.split(".")[0]
    for lbl in (primary_label, primary_label.translate(_DELEET_TABLE)):
        typo_brand = _TYPO_LOOKUP.get(lbl)
        if typo_brand:
            official_roots = PROTECTED_BRANDS[typo_brand]
            if root not in official_roots and not any(host.endswith("." + off) for off in official_roots):
                return 0.90, typo_brand

    return 0.0, None


def compute_brand_impersonation_details(hostname: str, claimed_brand_text: str = "") -> dict:
    """
    Model 3: Brand Impersonation Detector.
    Combines edit distance, character homoglyphs, Punycode/IDN checks, and
    claimed-brand vs. root-domain mismatch without flagging official domains
    or treating a brand mention alone as proof.
    """
    host = (hostname or "").lower().strip().rstrip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    root = extract_root_domain(host)

    is_punycode = 1 if ("xn--" in host or any(ord(c) > 127 for c in host)) else 0
    has_homoglyph = 1 if (host != host.translate(_DELEET_TABLE) and detect_brand_impersonation(host)[0] >= 0.80) else 0

    score, matched_brand = detect_brand_impersonation(host)
    edit_dist = 99
    if matched_brand:
        primary_label = root.split(".")[0]
        if primary_label == matched_brand:
            edit_dist = 0
        elif primary_label in _TYPO_LOOKUP or primary_label.translate(_DELEET_TABLE) in _TYPO_LOOKUP:
            edit_dist = 1
        else:
            edit_dist = 2

    claimed_mismatch = 0
    claimed_brand = None
    if claimed_brand_text:
        ct = re.sub(r"[^a-z0-9 ]", " ", claimed_brand_text.lower())
        for brand, official_roots in PROTECTED_BRANDS.items():
            if len(brand) >= 6 and brand in ct and root not in official_roots and not any(host.endswith("." + off) for off in official_roots):
                claimed_mismatch = 1
                claimed_brand = brand
                break

    evidence: list[str] = []
    if score >= 0.80 and matched_brand:
        evidence.append(f"Domain '{root}' resembles protected brand '{matched_brand}' without matching its official domain.")
    if is_punycode:
        evidence.append("Domain uses Punycode (xn--) or non-ASCII internationalized characters.")
    if has_homoglyph:
        evidence.append("Domain contains lookalike digit/character substitutions matching a known brand.")
    if claimed_mismatch and claimed_brand:
        evidence.append(f"Page title/metadata references '{claimed_brand}' while hosted on '{root}'.")

    # Never mark claimed brand mention alone as definitive high risk without corroboration
    effective_score = score
    if claimed_mismatch and effective_score == 0.0:
        effective_score = 0.35

    return {
        "brand_similarity_score": round(float(effective_score), 4),
        "typosquat_edit_distance": int(edit_dist),
        "matched_brand": matched_brand or claimed_brand,
        "is_punycode": int(is_punycode),
        "has_homoglyph": int(has_homoglyph),
        "claimed_brand_mismatch": int(claimed_mismatch),
        "evidence": evidence,
    }


def extract_url_features(url: str) -> dict:
    """
    Extract the standardized URL-only feature dictionary for a single URL.
    Canonicalizes leading 'www.' prior to lexical computation so classifiers do
    not overfit to 'www.' dataset collection artifacts (e.g., PhiUSIIL benign crawls).
    """
    raw = (url or "").strip()
    if raw and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower().strip().rstrip(".")
    root = extract_root_domain(host)

    # Strip leading 'www.' strictly for lexical calculation (keep real host/url in metadata)
    host_lex = host[4:] if host.startswith("www.") else host
    raw_lex = re.sub(r"^(https?://)www\.", r"\1", raw, flags=re.I)

    parts = [p for p in host_lex.split(".") if p]
    tld = parts[-1] if len(parts) > 1 else "com"
    num_subdomains = max(0, len(parts) - 2)
    is_ip = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or (":" in host and "[" in (parsed.netloc or "")) else 0
    is_punycode = 1 if ("xn--" in host or any(ord(c) > 127 for c in host)) else 0

    port = parsed.port
    has_unusual_port = 1 if (port is not None and port not in (80, 443)) else 0
    is_shortener = 1 if (host in URL_SHORTENER_DOMAINS or root in URL_SHORTENER_DOMAINS) else 0

    pct_enc = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    has_at_trick = 1 if "@" in (parsed.netloc or "") else 0
    has_obf = 1 if (pct_enc > 0 or has_at_trick) else 0

    url_len = len(raw_lex)
    letters = len(re.findall(r"[a-zA-Z]", raw_lex))
    digits_url = len(re.findall(r"[0-9]", raw_lex))
    digits_dom = len(re.findall(r"[0-9]", host_lex))
    special_chars = len(re.findall(r"[^a-zA-Z0-9.]", raw_lex))
    cont_cnt = sum(1 for i in range(1, url_len) if raw_lex[i] == raw_lex[i - 1])
    char_cont = cont_cnt / (url_len - 1) if url_len > 1 else 0.0

    brand_info = compute_brand_impersonation_details(host)
    kw_count = len(_KEYWORD_RE.findall(raw_lex))

    return {
        "url": raw,
        "domain": host,
        "root_domain": root,
        "url_length": int(url_len),
        "domain_length": int(len(host_lex)),
        "path_length": int(len(parsed.path or "")),
        "query_length": int(len(parsed.query or "")),
        "num_subdomains": int(num_subdomains),
        "num_dots": int(raw_lex.count(".")),
        "num_hyphens_domain": int(host_lex.count("-")),
        "num_digits_url": int(digits_url),
        "num_digits_domain": int(digits_dom),
        "num_special_chars": int(special_chars),
        "is_ip_address": int(is_ip),
        "is_punycode_or_idn": int(is_punycode),
        "has_unusual_port": int(has_unusual_port),
        "is_url_shortener": int(is_shortener),
        "has_url_obfuscation": int(has_obf),
        "url_entropy": round(_shannon_entropy(raw_lex), 4),
        "domain_entropy": round(_shannon_entropy(host_lex), 4),
        "tld_length": int(len(tld)),
        "is_suspicious_tld": int(tld in SUSPICIOUS_COMMERCE_TLDS),
        "suspicious_keyword_count": int(kw_count),
        "is_https": 1 if scheme == "https" else 0,
        "brand_similarity_score": float(brand_info["brand_similarity_score"]),
        "typosquat_edit_distance": int(brand_info["typosquat_edit_distance"]),
        "char_continuation_rate": round(char_cont, 6),
        "letter_ratio": round(letters / url_len, 6) if url_len else 0.0,
        "digit_ratio": round(digits_url / url_len, 6) if url_len else 0.0,
        "tld": tld,
        "matched_brand": brand_info["matched_brand"],
    }


def extract_url_features_batch(urls: pd.Series | list[str]) -> pd.DataFrame:
    """Extract URL_FEATURE_COLUMNS over a collection of URLs cleanly."""
    rows = [extract_url_features(str(u)) for u in urls]
    return pd.DataFrame(rows)


def _extract_host_series(df: pd.DataFrame) -> pd.Series:
    """Resolve lowercase domain/hostname strings from Domain, hostname, or URL columns."""
    if "Domain" in df.columns and df["Domain"].notna().any():
        hosts = df["Domain"].fillna("").astype(str)
    elif "hostname" in df.columns and df["hostname"].notna().any():
        hosts = df["hostname"].fillna("").astype(str)
    elif "domain" in df.columns and df["domain"].notna().any():
        hosts = df["domain"].fillna("").astype(str)
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
    Legacy compatibility helper computing ENGINEERED_FEATURE_COLUMNS for PhiUSIIL-aligned
    dataframes. New multi-model pipelines use extract_url_features_batch() and src/dom_features.py.
    """
    out = pd.DataFrame(index=df.index)
    hosts = _extract_host_series(df)

    out["DomainHyphenCount"] = hosts.str.count("-").astype(float)
    out["DomainDigitCount"] = hosts.str.count(r"\d").astype(float)

    if "TLD" in df.columns:
        tlds = df["TLD"].fillna("").astype(str).str.lower().str.strip().str.lstrip(".")
    else:
        tlds = hosts.str.split(".").str[-1].fillna("")
    out["IsSuspiciousStoreTLD"] = tlds.isin(SUSPICIOUS_COMMERCE_TLDS).astype(float)

    kw_pattern = r"(?:" + "|".join(re.escape(k) for k in SCAM_DOMAIN_KEYWORDS) + r")"
    out["HasScamDomainKeyword"] = hosts.str.contains(kw_pattern, regex=True, na=False).astype(float)

    scores = np.zeros(len(df), dtype=float)
    if len(df) <= 50:
        for idx_pos, h in enumerate(hosts):
            scores[idx_pos] = detect_brand_impersonation(h)[0]
    else:
        unique_hosts = hosts.unique()
        host_score_map = {h: detect_brand_impersonation(h)[0] for h in unique_hosts}
        scores = hosts.map(host_score_map).fillna(0.0).to_numpy(dtype=float)
    out["BrandImpersonationScore"] = scores

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
