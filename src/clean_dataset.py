"""
src/clean_dataset.py — Dataset Cleaning, De-biasing & Real-World Enrichment

Addresses false positives on legitimate websites caused by biases in raw PhiUSIIL:
1. Deduplicates exact rows and duplicate URLs; caps over-represented domains.
2. Sanitizes invalid values and winsorizes extreme scraper outliers.
3. Reduces over-representation of dead/empty 404 phishing stubs (LineOfCode <= 15)
   so the model does not equate lightweight valid pages with phishing.
4. Enriches the dataset with:
   - Live-extracted feature vectors from real, diverse legitimate websites
     (deep paths, query strings, non-www domains, .io/.dev/.app/.edu/.org TLDs).
   - Realistic augmented valid webpages (SPAs, docs, login portals, deep URLs).
   - Realistic active phishing webpages (credential harvesting, external form submit,
     suspicious TLDs, obfuscation, IP hosts, domain-brand mismatch).
"""

import os
import re
import time
import urllib.request
from urllib.parse import urlparse
import numpy as np
import pandas as pd

DATASET_PATH = os.path.join("dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")

LIVE_VALID_URLS = [
    "https://docs.python.org/3/library/os.html",
    "https://docs.python.org/3/tutorial/index.html",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/explore",
    "https://github.com/features",
    "https://stackoverflow.com/questions",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://scikit-learn.org/stable/user_guide.html",
    "https://pandas.pydata.org/docs/getting_started/index.html",
    "https://xgboost.readthedocs.io/en/stable/",
    "https://react.dev/learn",
    "https://vitejs.dev/guide/",
    "https://tailwindcss.com/docs/installation",
    "https://vercel.com/docs",
    "https://huggingface.co/models",
    "https://pypi.org/search/?q=fastapi",
    "https://www.npmjs.com/search?q=react",
    "https://news.ycombinator.com/news",
    "https://arxiv.org/list/cs.CR/recent",
    "https://www.w3.org/TR/",
    "https://www.cloudflare.com/learning/security/what-is-phishing/",
    "https://letsencrypt.org/getting-started/",
    "https://owasp.org/www-project-top-ten/",
    "https://cve.mitre.org/cve/search_cve_list.html",
    "https://www.nist.gov/cyberframework",
    "https://httpbin.org/forms/post",
    "https://example.com/",
    "https://example.org/",
]


def extract_live_features(url: str, timeout: int = 8) -> dict | None:
    """Fetch a live webpage and compute the 55-column PhiUSIIL-aligned feature row."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read(500_000).decode("utf-8", errors="ignore")
    except Exception:
        return None

    if len(html) < 200:
        return None

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else "com"
    no_sub = max(0, len(parts) - 2)
    is_ip = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0

    url_len = len(url)
    obf_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    letters = len(re.findall(r"[a-zA-Z]", url))
    digits = len(re.findall(r"[0-9]", url))
    eq_cnt = url.count("=")
    qm_cnt = url.count("?")
    amp_cnt = url.count("&")
    special_cnt = len(re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", url))

    cont_cnt = sum(1 for i in range(1, url_len) if url[i] == url[i - 1])
    char_cont = cont_cnt / (url_len - 1) if url_len > 1 else 0.0

    lines = html.splitlines()
    loc = max(1, len(lines))
    max_line = max((len(l) for l in lines), default=0)

    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title_raw = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
    has_title = 1 if title_raw else 0
    title_clean = re.sub(r"[^a-z0-9 ]", " ", title_raw.lower())
    title_words = [w for w in title_clean.split() if w]

    domain_words = [w for w in re.sub(r"[^a-z0-9 ]", " ", hostname).split() if len(w) > 2]
    d_matches = sum(1 for w in domain_words if w in title_words or w in title_clean)
    d_score = min(100.0, (d_matches / len(domain_words)) * 100.0) if domain_words else 0.0

    url_words = [w for w in re.sub(r"[^a-z0-9 ]", " ", url.lower()).split() if len(w) > 2]
    u_matches = sum(1 for w in url_words if w in title_words or w in title_clean)
    u_score = min(100.0, (u_matches / len(url_words)) * 100.0) if url_words else 0.0

    has_favicon = 1 if re.search(r"<link[^>]*rel=['\"]?[^'\"]*icon", html, re.I) else 0
    has_desc = 1 if re.search(r"<meta[^>]*name=['\"]description['\"]", html, re.I) else 0
    is_resp = 1 if re.search(r"<meta[^>]*name=['\"]viewport['\"]", html, re.I) else 0

    no_popup = html.lower().count("window.open")
    no_redirect = len(re.findall(r"http-equiv=['\"]refresh['\"]", html, re.I))
    no_iframe = len(re.findall(r"<iframe\b", html, re.I))

    ext_submit = 0
    for m in re.finditer(r"<form[^>]*action=['\"]([^'\"]+)['\"]", html, re.I):
        act = m.group(1).lower()
        if act.startswith("http") and hostname not in act:
            ext_submit = 1

    social_domains = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com", "github.com")
    hrefs = re.findall(r"<a[^>]*href=['\"]([^'\"]*)['\"]", html, re.I)
    has_social = 1 if any(any(s in h.lower() for s in social_domains) for h in hrefs) else 0

    has_submit = 1 if re.search(r"(<input[^>]*type=['\"]submit['\"]|<button\b)", html, re.I) else 0
    has_hidden = 1 if re.search(r"<input[^>]*type=['\"]hidden['\"]", html, re.I) else 0
    has_pwd = 1 if re.search(r"<input[^>]*type=['\"]password['\"]", html, re.I) else 0

    lower_html = html.lower()
    bank = 1 if any(k in lower_html for k in ("bank", "banking", "account", "login", "signin", "verify", "secure")) else 0
    pay = 1 if any(k in lower_html for k in ("payment", "pay now", "checkout", "billing", "invoice")) else 0
    crypto = 1 if any(k in lower_html for k in ("bitcoin", "ethereum", "crypto", "wallet", "blockchain")) else 0
    has_copy = 1 if any(k in lower_html for k in ("©", "&copy;", "copyright", "all rights reserved")) else 0

    no_img = len(re.findall(r"<img\b", html, re.I))
    no_css = len(re.findall(r"<link[^>]*rel=['\"]stylesheet['\"]", html, re.I))
    no_js = len(re.findall(r"<script[^>]*src=", html, re.I))

    self_ref, empty_ref, ext_ref = 0, 0, 0
    for h in hrefs:
        hl = h.strip().lower()
        if not hl or hl == "#" or hl.startswith("javascript:"):
            empty_ref += 1
        elif hl.startswith("http"):
            lh = (urlparse(hl).hostname or "").lower()
            if lh == hostname or lh.endswith("." + hostname):
                self_ref += 1
            else:
                ext_ref += 1
        else:
            self_ref += 1

    return {
        "URL": url,
        "URLLength": url_len,
        "Domain": hostname,
        "DomainLength": len(hostname),
        "IsDomainIP": is_ip,
        "TLD": tld,
        "URLSimilarityIndex": 100.0,
        "CharContinuationRate": round(char_cont, 6),
        "TLDLegitimateProb": 0.5,
        "URLCharProb": 0.05,
        "TLDLength": len(tld),
        "NoOfSubDomain": no_sub,
        "HasObfuscation": 1 if obf_chars > 0 else 0,
        "NoOfObfuscatedChar": obf_chars,
        "ObfuscationRatio": round(obf_chars / url_len, 6) if url_len else 0.0,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": round(letters / url_len, 6) if url_len else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": round(digits / url_len, 6) if url_len else 0.0,
        "NoOfEqualsInURL": eq_cnt,
        "NoOfQMarkInURL": qm_cnt,
        "NoOfAmpersandInURL": amp_cnt,
        "NoOfOtherSpecialCharsInURL": special_cnt,
        "SpacialCharRatioInURL": round(special_cnt / url_len, 6) if url_len else 0.0,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
        "LineOfCode": loc,
        "LargestLineLength": max_line,
        "HasTitle": has_title,
        "Title": title_raw[:120] if title_raw else "Page",
        "DomainTitleMatchScore": round(d_score, 2),
        "URLTitleMatchScore": round(u_score, 2),
        "HasFavicon": has_favicon,
        "Robots": 0,
        "IsResponsive": is_resp,
        "NoOfURLRedirect": no_redirect,
        "NoOfSelfRedirect": 0,
        "HasDescription": has_desc,
        "NoOfPopup": no_popup,
        "NoOfiFrame": no_iframe,
        "HasExternalFormSubmit": ext_submit,
        "HasSocialNet": has_social,
        "HasSubmitButton": has_submit,
        "HasHiddenFields": has_hidden,
        "HasPasswordField": has_pwd,
        "Bank": bank,
        "Pay": pay,
        "Crypto": crypto,
        "HasCopyrightInfo": has_copy,
        "NoOfImage": no_img,
        "NoOfCSS": no_css,
        "NoOfJS": no_js,
        "NoOfSelfRef": self_ref,
        "NoOfEmptyRef": empty_ref,
        "NoOfExternalRef": ext_ref,
        "label": 1,
    }


def generate_modern_valid_samples(base_legit: pd.DataFrame, n_samples: int = 35000, seed: int = 42) -> pd.DataFrame:
    """
    Create realistic valid webpage profiles derived from cleaned legitimate samples
    to eliminate PhiUSIIL's homepage-only bias (www-only, URLLength<=57, 0 query params,
    always heavy external links, legacy-only TLDs).
    """
    rng = np.random.default_rng(seed)
    sampled = base_legit.sample(n=n_samples, replace=True, random_state=seed).copy().reset_index(drop=True)

    modern_tlds = ["com", "org", "net", "io", "dev", "app", "ai", "co", "edu", "gov", "in", "uk", "de"]
    tld_probs = [0.34, 0.14, 0.08, 0.10, 0.07, 0.06, 0.04, 0.04, 0.04, 0.02, 0.03, 0.02, 0.02]

    # Split into realistic valid page archetypes
    n1 = int(n_samples * 0.45)  # Deep paths & query-param pages (docs, blogs, portals)
    n2 = int(n_samples * 0.35)  # Lightweight / modern SPAs & portals (low LineOfCode / external refs)
    n3 = n_samples - n1 - n2    # Valid login / auth pages (HasPasswordField=1, no external submit)

    # Common realistic TLD & subdomain diversity
    chosen_tlds = rng.choice(modern_tlds, size=n_samples, p=tld_probs)
    sampled["TLD"] = chosen_tlds
    sampled["TLDLength"] = [len(t) for t in chosen_tlds]
    sampled["NoOfSubDomain"] = rng.choice([0, 1, 2], size=n_samples, p=[0.52, 0.42, 0.06])
    sampled["Robots"] = rng.choice([0, 1], size=n_samples, p=[0.85, 0.15])
    sampled["IsHTTPS"] = 1
    sampled["IsDomainIP"] = 0
    sampled["HasObfuscation"] = 0
    sampled["NoOfObfuscatedChar"] = 0
    sampled["ObfuscationRatio"] = 0.0
    sampled["HasExternalFormSubmit"] = 0

    # Archetype 1: Deep valid URLs with paths / query params
    idx1 = sampled.index[:n1]
    url_lens_1 = rng.integers(38, 135, size=n1)
    sampled.loc[idx1, "URLLength"] = url_lens_1
    sampled.loc[idx1, "NoOfLettersInURL"] = (url_lens_1 * rng.uniform(0.68, 0.85, size=n1)).astype(int)
    sampled.loc[idx1, "NoOfDegitsInURL"] = rng.integers(0, 8, size=n1)
    q_has = rng.random(size=n1) < 0.45
    sampled.loc[idx1, "NoOfQMarkInURL"] = np.where(q_has, 1, 0)
    sampled.loc[idx1, "NoOfEqualsInURL"] = np.where(q_has, rng.integers(1, 4, size=n1), 0)
    sampled.loc[idx1, "NoOfAmpersandInURL"] = np.where(q_has, rng.integers(0, 3, size=n1), 0)
    sampled.loc[idx1, "NoOfExternalRef"] = rng.integers(2, 35, size=n1)
    sampled.loc[idx1, "NoOfSelfRef"] = rng.integers(4, 60, size=n1)
    sampled.loc[idx1, "LineOfCode"] = rng.integers(60, 1200, size=n1)
    sampled.loc[idx1, "HasSocialNet"] = rng.choice([0, 1], size=n1, p=[0.45, 0.55])
    sampled.loc[idx1, "HasCopyrightInfo"] = rng.choice([0, 1], size=n1, p=[0.25, 0.75])
    sampled.loc[idx1, "DomainTitleMatchScore"] = rng.choice([0.0, 20.0, 33.3, 50.0, 100.0], size=n1, p=[0.20, 0.15, 0.20, 0.25, 0.20])

    # Archetype 2: Clean lightweight / SPA pages (React, Vite, Next.js, minimalist sites)
    idx2 = sampled.index[n1:n1 + n2]
    url_lens_2 = rng.integers(22, 95, size=n2)
    sampled.loc[idx2, "URLLength"] = url_lens_2
    sampled.loc[idx2, "NoOfLettersInURL"] = (url_lens_2 * rng.uniform(0.72, 0.88, size=n2)).astype(int)
    sampled.loc[idx2, "NoOfDegitsInURL"] = rng.integers(0, 5, size=n2)
    q_has_2 = rng.random(size=n2) < 0.25
    sampled.loc[idx2, "NoOfQMarkInURL"] = np.where(q_has_2, 1, 0)
    sampled.loc[idx2, "NoOfEqualsInURL"] = np.where(q_has_2, rng.integers(1, 3, size=n2), 0)
    sampled.loc[idx2, "NoOfAmpersandInURL"] = 0
    sampled.loc[idx2, "LineOfCode"] = rng.integers(15, 220, size=n2)
    sampled.loc[idx2, "LargestLineLength"] = rng.integers(120, 4000, size=n2)
    sampled.loc[idx2, "NoOfExternalRef"] = rng.choice([0, 1, 2, 3, 5, 8, 12], size=n2, p=[0.25, 0.15, 0.15, 0.15, 0.15, 0.10, 0.05])
    sampled.loc[idx2, "NoOfSelfRef"] = rng.choice([0, 1, 2, 3, 5, 8, 12, 16], size=n2, p=[0.18, 0.17, 0.15, 0.15, 0.15, 0.10, 0.05, 0.05])
    sampled.loc[idx2, "NoOfEmptyRef"] = rng.choice([0, 1, 2], size=n2, p=[0.80, 0.15, 0.05])
    sampled.loc[idx2, "NoOfImage"] = rng.choice([0, 1, 2, 3, 5, 8], size=n2, p=[0.20, 0.25, 0.20, 0.15, 0.10, 0.10])
    sampled.loc[idx2, "NoOfCSS"] = rng.choice([0, 1, 2, 3, 4], size=n2, p=[0.15, 0.35, 0.25, 0.15, 0.10])
    sampled.loc[idx2, "NoOfJS"] = rng.choice([0, 1, 2, 3, 5, 8], size=n2, p=[0.20, 0.25, 0.20, 0.15, 0.10, 0.10])
    sampled.loc[idx2, "HasSocialNet"] = rng.choice([0, 1], size=n2, p=[0.75, 0.25])
    sampled.loc[idx2, "HasCopyrightInfo"] = rng.choice([0, 1], size=n2, p=[0.45, 0.55])
    sampled.loc[idx2, "HasDescription"] = rng.choice([0, 1], size=n2, p=[0.45, 0.55])
    sampled.loc[idx2, "DomainTitleMatchScore"] = rng.choice([0.0, 25.0, 50.0, 100.0], size=n2, p=[0.25, 0.25, 0.25, 0.25])

    # Allow ~25% of non-credential informational pages (Archetype 1 & 2) to be benign HTTP
    # (including pure-HTML static pages with 0 JS / 0 CSS) so IsHTTPS=0 without login traps isn't flagged.
    info_mask = (sampled.index < n1 + n2) & (sampled["HasPasswordField"] == 0) & (sampled["Bank"] == 0) & (sampled["Pay"] == 0) & (sampled["Crypto"] == 0)
    http_mask = info_mask & (rng.random(size=n_samples) < 0.25)
    sampled.loc[http_mask, "IsHTTPS"] = 0

    # Archetype 3: Valid HTTPS login / authentication portals
    idx3 = sampled.index[n1 + n2:]
    url_lens_3 = rng.integers(28, 90, size=n3)
    sampled.loc[idx3, "URLLength"] = url_lens_3
    sampled.loc[idx3, "NoOfLettersInURL"] = (url_lens_3 * rng.uniform(0.72, 0.86, size=n3)).astype(int)
    sampled.loc[idx3, "NoOfDegitsInURL"] = rng.integers(0, 4, size=n3)
    q_has_3 = rng.random(size=n3) < 0.35
    sampled.loc[idx3, "NoOfQMarkInURL"] = np.where(q_has_3, 1, 0)
    sampled.loc[idx3, "NoOfEqualsInURL"] = np.where(q_has_3, 1, 0)
    sampled.loc[idx3, "NoOfAmpersandInURL"] = 0
    sampled.loc[idx3, "LineOfCode"] = rng.integers(20, 350, size=n3)
    sampled.loc[idx3, "NoOfExternalRef"] = rng.choice([0, 1, 2, 3, 5, 8], size=n3, p=[0.30, 0.20, 0.20, 0.15, 0.10, 0.05])
    sampled.loc[idx3, "NoOfSelfRef"] = rng.choice([0, 1, 2, 3, 5, 8, 12], size=n3, p=[0.20, 0.20, 0.18, 0.15, 0.12, 0.10, 0.05])
    sampled.loc[idx3, "NoOfEmptyRef"] = rng.choice([0, 1], size=n3, p=[0.85, 0.15])
    sampled.loc[idx3, "NoOfImage"] = rng.choice([0, 1, 2, 3, 5], size=n3, p=[0.20, 0.30, 0.25, 0.15, 0.10])
    sampled.loc[idx3, "HasPasswordField"] = 1
    sampled.loc[idx3, "HasSubmitButton"] = 1
    sampled.loc[idx3, "HasHiddenFields"] = rng.choice([0, 1], size=n3, p=[0.5, 0.5])
    sampled.loc[idx3, "HasExternalFormSubmit"] = 0
    sampled.loc[idx3, "HasFavicon"] = 1
    sampled.loc[idx3, "IsResponsive"] = 1
    sampled.loc[idx3, "HasSocialNet"] = rng.choice([0, 1], size=n3, p=[0.75, 0.25])
    sampled.loc[idx3, "HasCopyrightInfo"] = rng.choice([0, 1], size=n3, p=[0.35, 0.65])
    sampled.loc[idx3, "HasDescription"] = rng.choice([0, 1], size=n3, p=[0.45, 0.55])
    sampled.loc[idx3, "Bank"] = rng.choice([0, 1], size=n3, p=[0.4, 0.6])
    sampled.loc[idx3, "DomainTitleMatchScore"] = rng.choice([0.0, 33.3, 50.0, 100.0], size=n3, p=[0.25, 0.25, 0.25, 0.25])

    # Keep ratios consistent
    sampled["LetterRatioInURL"] = (sampled["NoOfLettersInURL"] / sampled["URLLength"]).round(6)
    sampled["DegitRatioInURL"] = (sampled["NoOfDegitsInURL"] / sampled["URLLength"]).round(6)
    sampled["URLTitleMatchScore"] = np.minimum(100.0, sampled["DomainTitleMatchScore"] + rng.choice([0.0, 10.0], size=n_samples))
    sampled["URL"] = [f"https://valid-site-{i}.{t}/page" for i, t in enumerate(chosen_tlds)]
    sampled["Domain"] = [f"valid-site-{i}.{t}" for i, t in enumerate(chosen_tlds)]
    sampled["label"] = 1
    return sampled


def generate_active_phishing_samples(base_phish: pd.DataFrame, n_samples: int = 15000, seed: int = 99) -> pd.DataFrame:
    """
    Generate active, realistic phishing pages (non-404) that exhibit genuine malicious
    signals (external form submit, suspicious TLDs, obfuscation, IP host, dummy links,
    domain-title mismatch + credential fields) even when hosted over HTTPS with realistic HTML.
    """
    rng = np.random.default_rng(seed)
    sampled = base_phish.sample(n=n_samples, replace=True, random_state=seed).copy().reset_index(drop=True)

    susp_tlds = ["xyz", "top", "tk", "ml", "cf", "gq", "ga", "buzz", "icu", "click", "link", "vip", "work", "com", "net"]
    tld_p = [0.14, 0.10, 0.07, 0.06, 0.06, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.04, 0.05, 0.12, 0.06]
    chosen_tlds = rng.choice(susp_tlds, size=n_samples, p=tld_p)

    sampled["TLD"] = chosen_tlds
    sampled["TLDLength"] = [len(t) for t in chosen_tlds]
    sampled["IsHTTPS"] = rng.choice([0, 1], size=n_samples, p=[0.55, 0.45])
    sampled["URLLength"] = rng.integers(32, 160, size=n_samples)
    sampled["DomainLength"] = rng.integers(14, 48, size=n_samples)
    sampled["NoOfSubDomain"] = rng.choice([0, 1, 2, 3, 4], size=n_samples, p=[0.20, 0.25, 0.25, 0.20, 0.10])
    sampled["LineOfCode"] = rng.integers(35, 650, size=n_samples)
    sampled["NoOfExternalRef"] = rng.integers(0, 35, size=n_samples)
    sampled["NoOfSelfRef"] = rng.integers(0, 5, size=n_samples)
    sampled["NoOfEmptyRef"] = rng.choice([0, 3, 6, 10, 15], size=n_samples, p=[0.25, 0.20, 0.25, 0.20, 0.10])
    sampled["NoOfiFrame"] = rng.choice([0, 1, 2, 3], size=n_samples, p=[0.50, 0.20, 0.20, 0.10])
    sampled["HasTitle"] = 1
    sampled["DomainTitleMatchScore"] = rng.choice([0.0, 5.0, 10.0], size=n_samples, p=[0.75, 0.15, 0.10])
    sampled["URLTitleMatchScore"] = sampled["DomainTitleMatchScore"]
    sampled["HasPasswordField"] = rng.choice([0, 1], size=n_samples, p=[0.20, 0.80])
    sampled["HasSubmitButton"] = 1
    sampled["HasHiddenFields"] = rng.choice([0, 1], size=n_samples, p=[0.30, 0.70])
    sampled["HasExternalFormSubmit"] = rng.choice([0, 1], size=n_samples, p=[0.40, 0.60])
    sampled["HasObfuscation"] = rng.choice([0, 1], size=n_samples, p=[0.70, 0.30])
    sampled["NoOfObfuscatedChar"] = np.where(sampled["HasObfuscation"] == 1, rng.integers(2, 15, size=n_samples), 0)
    sampled["IsDomainIP"] = rng.choice([0, 1], size=n_samples, p=[0.90, 0.10])
    sampled["Bank"] = rng.choice([0, 1], size=n_samples, p=[0.35, 0.65])
    sampled["Pay"] = rng.choice([0, 1], size=n_samples, p=[0.65, 0.35])
    sampled["HasSocialNet"] = 0
    sampled["HasCopyrightInfo"] = rng.choice([0, 1], size=n_samples, p=[0.75, 0.25])

    sampled["NoOfLettersInURL"] = (sampled["URLLength"] * rng.uniform(0.55, 0.78, size=n_samples)).astype(int)
    sampled["NoOfDegitsInURL"] = rng.integers(2, 16, size=n_samples)
    sampled["LetterRatioInURL"] = (sampled["NoOfLettersInURL"] / sampled["URLLength"]).round(6)
    sampled["DegitRatioInURL"] = (sampled["NoOfDegitsInURL"] / sampled["URLLength"]).round(6)
    sampled["ObfuscationRatio"] = (sampled["NoOfObfuscatedChar"] / sampled["URLLength"]).round(6)
    sampled["URL"] = [f"http://verify-login-{i}.{t}/auth" for i, t in enumerate(chosen_tlds)]
    sampled["Domain"] = [f"verify-login-{i}.{t}" for i, t in enumerate(chosen_tlds)]
    sampled["label"] = 0
    return sampled


def main():
    print(f"Loading raw dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    cols = df.columns.tolist()
    print(f"Initial shape: {df.shape}")

    # Make script idempotent by stripping any prior synthetic rows before regenerating
    if "Domain" in df.columns:
        df = df[~df["Domain"].astype(str).str.startswith(("valid-site-", "verify-login-"))].copy()

    # 1. Deduplicate exact rows and duplicate URLs
    df = df.drop_duplicates()
    if "URL" in df.columns:
        df = df.drop_duplicates(subset=["URL"], keep="first")

    # Cap duplicate Domain rows to max 3 per domain to prevent domain memorization
    if "Domain" in df.columns:
        df = df.groupby("Domain", group_keys=False).head(3)

    # 2. Sanitize TLD and numeric bounds
    df["TLD"] = df["TLD"].fillna("com").astype(str).str.lower().str.strip().str.lstrip(".")
    ratio_cols = ["CharContinuationRate", "ObfuscationRatio", "LetterRatioInURL", "DegitRatioInURL", "SpacialCharRatioInURL"]
    for c in ratio_cols:
        df[c] = df[c].clip(lower=0.0, upper=1.0)

    # Clip extreme scraper tail outliers
    clip_bounds = {
        "URLLength": (5, 500),
        "DomainLength": (3, 120),
        "LineOfCode": (1, 30000),
        "LargestLineLength": (1, 500000),
        "NoOfImage": (0, 1000),
        "NoOfCSS": (0, 250),
        "NoOfJS": (0, 250),
        "NoOfSelfRef": (0, 1500),
        "NoOfExternalRef": (0, 1500),
        "NoOfEmptyRef": (0, 150),
        "NoOfiFrame": (0, 50),
        "NoOfPopup": (0, 30),
        "DomainTitleMatchScore": (0.0, 100.0),
        "URLTitleMatchScore": (0.0, 100.0),
    }
    for col, (lo, hi) in clip_bounds.items():
        if col in df.columns:
            df[col] = df[col].clip(lower=lo, upper=hi)

    # 3. Reduce over-represented dead/empty 404 phishing stubs so lightweight valid pages aren't flagged
    is_dead_stub = (
        (df["label"] == 0)
        & (df["LineOfCode"] <= 15)
        & (df["NoOfExternalRef"] == 0)
        & (df["NoOfSelfRef"] == 0)
        & (df["NoOfImage"] == 0)
        & (df["HasTitle"] == 0)
    )
    dead_stubs = df[is_dead_stub]
    non_dead = df[~is_dead_stub]
    if len(dead_stubs) > 10000:
        dead_stubs = dead_stubs.sample(n=10000, random_state=42)
    df_clean = pd.concat([non_dead, dead_stubs], ignore_index=True)
    print(f"After cleaning & dead-stub balancing: {df_clean.shape}")

    # 4. Scrape live legitimate websites for authentic real-world vectors
    print("Scraping live valid websites for authentic feature vectors...")
    live_rows = []
    for u in LIVE_VALID_URLS:
        row = extract_live_features(u)
        if row:
            live_rows.append(row)
    print(f"Successfully extracted {len(live_rows)} live valid webpage profiles.")

    live_df = pd.DataFrame(live_rows) if live_rows else pd.DataFrame(columns=cols)

    # 5. Augment modern valid webpages & active phishing webpages
    legit_pool = df_clean[df_clean["label"] == 1]
    phish_pool = df_clean[df_clean["label"] == 0]

    modern_valid_df = generate_modern_valid_samples(legit_pool, n_samples=35000, seed=42)
    active_phish_df = generate_active_phishing_samples(phish_pool, n_samples=15000, seed=99)

    final_df = pd.concat([df_clean, live_df, modern_valid_df, active_phish_df], ignore_index=True)
    final_df = final_df[cols].sample(frac=1.0, random_state=42).reset_index(drop=True)

    print("Final dataset shape:", final_df.shape)
    print("Final class distribution:\n", final_df["label"].value_counts())

    final_df.to_csv(DATASET_PATH, index=False)
    print(f"Saved cleaned & updated dataset to {DATASET_PATH}")


if __name__ == "__main__":
    main()

