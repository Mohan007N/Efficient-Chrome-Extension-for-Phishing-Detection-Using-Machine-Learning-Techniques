"""
src/clean_dataset.py — Dataset Cleaning, De-biasing & Real-World Enrichment

Combines:
1. Cleaned & de-biased PhiUSIIL phishing dataset (deduplicated, bounded, 404 stubs capped)
2. Real-world live-discovered unauthorized, fake-shopping, and legitimate commerce/portal
   feature vectors from dataset/live_discovered_features.csv (or live fallback scraping)
3. Balanced modern legitimate storefronts/portals & stealthy HTTPS scam/unauthorized
   ecommerce/portal profiles without synthetic domain-prefix leakage.
"""

import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_forensics import extract_live_features

DATASET_PATH = os.path.join("dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
LIVE_FEATURES_PATH = os.path.join("dataset", "live_discovered_features.csv")

FALLBACK_LIVE_VALID_URLS = [
    "https://docs.python.org/3/library/os.html",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/explore",
    "https://stackoverflow.com/questions",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://scikit-learn.org/stable/user_guide.html",
    "https://www.flipkart.com/",
    "https://www.croma.com/",
    "https://www.tatacliq.com/",
    "https://www.shopify.com/",
    "https://www.target.com/",
    "https://www.ikea.com/",
]

SYNTHETIC_DOMAIN_PREFIXES = (
    "valid-site-",
    "verify-login-",
    "valid-shop-",
    "scam-shop-",
    "synth-valid-",
    "synth-phish-",
    "synth-shop-",
    "synth-scam-",
)


def _make_legit_domains(n: int, tlds: np.ndarray, rng: np.random.Generator, prefix: str = "synth-valid-") -> tuple[list[str], list[str]]:
    """Generate realistic varied legitimate domain names without artificial keyword bias."""
    brands = [
        "aurora", "veritas", "cobalt", "harbor", "summit", "meadow", "atlas", "meridian",
        "novacraft", "pioneer", "kinetix", "zenith", "horizon", "breeze", "craftsman", "nordic",
    ]
    domains, urls = [], []
    for i in range(n):
        b = brands[i % len(brands)]
        t = tlds[i]
        # Prefix tag stays only as metadata stripped during preprocessing; avoid leaking label in domain structure
        dom = f"{prefix}{b}{i}.{t}" if rng.random() < 0.7 else f"{prefix}{b}-store{i}.{t}"
        domains.append(dom)
        urls.append(f"https://www.{dom}/catalog/item-{i % 50}" if rng.random() < 0.5 else f"https://{dom}/products/{i % 50}")
    return domains, urls


def generate_modern_valid_samples(base_legit: pd.DataFrame, n_samples: int = 35000, seed: int = 42) -> pd.DataFrame:
    """Create realistic valid webpage profiles derived from cleaned legitimate samples."""
    rng = np.random.default_rng(seed)
    sampled = base_legit.sample(n=n_samples, replace=True, random_state=seed).copy().reset_index(drop=True)

    modern_tlds = ["com", "org", "net", "io", "dev", "app", "ai", "co", "edu", "gov", "in", "uk", "de"]
    tld_probs = [0.34, 0.14, 0.08, 0.10, 0.07, 0.06, 0.04, 0.04, 0.04, 0.02, 0.03, 0.02, 0.02]

    n1 = int(n_samples * 0.45)  # Deep paths & query-param pages
    n2 = int(n_samples * 0.35)  # Lightweight / modern SPAs
    n3 = n_samples - n1 - n2    # Valid login / auth portals

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

    info_mask = (sampled.index < n1 + n2) & (sampled["HasPasswordField"] == 0) & (sampled["Bank"] == 0) & (sampled["Pay"] == 0) & (sampled["Crypto"] == 0)
    http_mask = info_mask & (rng.random(size=n_samples) < 0.25)
    sampled.loc[http_mask, "IsHTTPS"] = 0

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

    sampled["LetterRatioInURL"] = (sampled["NoOfLettersInURL"] / sampled["URLLength"]).round(6)
    sampled["DegitRatioInURL"] = (sampled["NoOfDegitsInURL"] / sampled["URLLength"]).round(6)
    sampled["URLTitleMatchScore"] = np.minimum(100.0, sampled["DomainTitleMatchScore"] + rng.choice([0.0, 10.0], size=n_samples))
    doms, urls = _make_legit_domains(n_samples, chosen_tlds, rng, prefix="synth-valid-")
    sampled["Domain"] = doms
    sampled["URL"] = urls
    sampled["label"] = 1
    return sampled


def generate_active_phishing_samples(base_phish: pd.DataFrame, n_samples: int = 15000, seed: int = 99) -> pd.DataFrame:
    """Generate active non-404 credential phishing & brand-impersonation portal profiles."""
    rng = np.random.default_rng(seed)
    sampled = base_phish.sample(n=n_samples, replace=True, random_state=seed).copy().reset_index(drop=True)

    susp_tlds = ["xyz", "top", "tk", "ml", "cf", "gq", "ga", "buzz", "icu", "click", "link", "vip", "work", "com", "net", "in"]
    tld_p = [0.13, 0.09, 0.06, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.04, 0.05, 0.12, 0.06, 0.05]
    chosen_tlds = rng.choice(susp_tlds, size=n_samples, p=tld_p)

    sampled["TLD"] = chosen_tlds
    sampled["TLDLength"] = [len(t) for t in chosen_tlds]
    sampled["IsHTTPS"] = rng.choice([0, 1], size=n_samples, p=[0.45, 0.55])
    sampled["URLLength"] = rng.integers(32, 160, size=n_samples)
    sampled["DomainLength"] = rng.integers(14, 48, size=n_samples)
    sampled["NoOfSubDomain"] = rng.choice([0, 1, 2, 3, 4], size=n_samples, p=[0.20, 0.25, 0.25, 0.20, 0.10])
    sampled["LineOfCode"] = rng.integers(35, 650, size=n_samples)
    sampled["NoOfExternalRef"] = rng.integers(0, 35, size=n_samples)
    sampled["NoOfSelfRef"] = rng.integers(0, 5, size=n_samples)
    sampled["NoOfEmptyRef"] = rng.choice([0, 3, 6, 10, 15], size=n_samples, p=[0.25, 0.20, 0.25, 0.20, 0.10])
    sampled["NoOfiFrame"] = rng.choice([0, 1, 2, 3], size=n_samples, p=[0.50, 0.20, 0.20, 0.10])
    sampled["HasTitle"] = 1
    sampled["DomainTitleMatchScore"] = rng.choice([0.0, 5.0, 10.0, 33.3], size=n_samples, p=[0.65, 0.15, 0.10, 0.10])
    sampled["URLTitleMatchScore"] = sampled["DomainTitleMatchScore"]
    sampled["HasPasswordField"] = rng.choice([0, 1], size=n_samples, p=[0.20, 0.80])
    sampled["HasSubmitButton"] = 1
    sampled["HasHiddenFields"] = rng.choice([0, 1], size=n_samples, p=[0.30, 0.70])
    sampled["HasExternalFormSubmit"] = rng.choice([0, 1], size=n_samples, p=[0.40, 0.60])
    sampled["HasObfuscation"] = rng.choice([0, 1], size=n_samples, p=[0.70, 0.30])
    sampled["NoOfObfuscatedChar"] = np.where(sampled["HasObfuscation"] == 1, rng.integers(2, 15, size=n_samples), 0)
    sampled["IsDomainIP"] = rng.choice([0, 1], size=n_samples, p=[0.90, 0.10])
    sampled["Bank"] = rng.choice([0, 1], size=n_samples, p=[0.35, 0.65])
    sampled["Pay"] = rng.choice([0, 1], size=n_samples, p=[0.60, 0.40])
    sampled["HasSocialNet"] = 0
    sampled["HasCopyrightInfo"] = rng.choice([0, 1], size=n_samples, p=[0.75, 0.25])

    sampled["NoOfLettersInURL"] = (sampled["URLLength"] * rng.uniform(0.55, 0.78, size=n_samples)).astype(int)
    sampled["NoOfDegitsInURL"] = rng.integers(2, 16, size=n_samples)
    sampled["LetterRatioInURL"] = (sampled["NoOfLettersInURL"] / sampled["URLLength"]).round(6)
    sampled["DegitRatioInURL"] = (sampled["NoOfDegitsInURL"] / sampled["URLLength"]).round(6)
    sampled["ObfuscationRatio"] = (sampled["NoOfObfuscatedChar"] / sampled["URLLength"]).round(6)

    lures = [
        "verify-login", "secure-account", "irctc-tatkal-help", "sbi-kyc-update",
        "hdfc-reward-claim", "amazon-prize-claim", "flipkart-refund-support", "paytm-wallet-verify",
    ]
    doms, urls = [], []
    for i, t in enumerate(chosen_tlds):
        d = f"synth-phish-{lures[i % len(lures)]}-{i}.{t}"
        doms.append(d)
        urls.append(f"https://{d}/auth" if sampled.loc[i, "IsHTTPS"] == 1 else f"http://{d}/auth")
    sampled["Domain"] = doms
    sampled["URL"] = urls
    sampled["label"] = 0
    return sampled


def generate_legitimate_ecommerce_samples(base_legit: pd.DataFrame, n_samples: int = 12000, seed: int = 123) -> pd.DataFrame:
    """Generate realistic legitimate shopping & booking portals."""
    rng = np.random.default_rng(seed)
    sampled = base_legit.sample(n=n_samples, replace=True, random_state=seed).copy().reset_index(drop=True)

    tlds = ["com", "co", "in", "uk", "de", "net", "org", "io", "shop", "store"]
    probs = [0.48, 0.08, 0.08, 0.08, 0.06, 0.05, 0.04, 0.05, 0.04, 0.04]
    chosen_tlds = rng.choice(tlds, size=n_samples, p=probs)

    sampled["TLD"] = chosen_tlds
    sampled["TLDLength"] = [len(t) for t in chosen_tlds]
    sampled["IsHTTPS"] = 1
    sampled["IsDomainIP"] = 0
    sampled["HasObfuscation"] = 0
    sampled["NoOfObfuscatedChar"] = 0
    sampled["ObfuscationRatio"] = 0.0
    sampled["NoOfSubDomain"] = rng.choice([0, 1], size=n_samples, p=[0.45, 0.55])
    sampled["DomainLength"] = rng.integers(8, 24, size=n_samples)
    sampled["URLLength"] = rng.integers(24, 95, size=n_samples)
    sampled["NoOfLettersInURL"] = (sampled["URLLength"] * rng.uniform(0.72, 0.88, size=n_samples)).astype(int)
    sampled["NoOfDegitsInURL"] = rng.integers(0, 4, size=n_samples)
    sampled["NoOfQMarkInURL"] = rng.choice([0, 1], size=n_samples, p=[0.75, 0.25])
    sampled["NoOfEqualsInURL"] = np.where(sampled["NoOfQMarkInURL"] == 1, rng.integers(1, 3, size=n_samples), 0)
    sampled["NoOfAmpersandInURL"] = 0
    sampled["LineOfCode"] = rng.integers(250, 4500, size=n_samples)
    sampled["LargestLineLength"] = rng.integers(400, 15000, size=n_samples)
    sampled["NoOfImage"] = rng.integers(15, 140, size=n_samples)
    sampled["NoOfCSS"] = rng.integers(2, 14, size=n_samples)
    sampled["NoOfJS"] = rng.integers(3, 24, size=n_samples)
    sampled["NoOfSelfRef"] = rng.integers(25, 180, size=n_samples)
    sampled["NoOfExternalRef"] = rng.integers(4, 35, size=n_samples)
    sampled["NoOfEmptyRef"] = rng.choice([0, 1, 2], size=n_samples, p=[0.70, 0.20, 0.10])
    sampled["NoOfiFrame"] = rng.choice([0, 1], size=n_samples, p=[0.80, 0.20])
    sampled["HasTitle"] = 1
    sampled["DomainTitleMatchScore"] = rng.choice([33.3, 50.0, 66.7, 100.0], size=n_samples, p=[0.15, 0.30, 0.20, 0.35])
    sampled["URLTitleMatchScore"] = np.minimum(100.0, sampled["DomainTitleMatchScore"] + 10.0)
    sampled["HasFavicon"] = 1
    sampled["IsResponsive"] = 1
    sampled["HasDescription"] = 1
    sampled["HasSocialNet"] = rng.choice([0, 1], size=n_samples, p=[0.15, 0.85])
    sampled["HasCopyrightInfo"] = rng.choice([0, 1], size=n_samples, p=[0.10, 0.90])
    sampled["HasSubmitButton"] = 1
    sampled["HasPasswordField"] = rng.choice([0, 1], size=n_samples, p=[0.65, 0.35])
    sampled["HasHiddenFields"] = rng.choice([0, 1], size=n_samples, p=[0.40, 0.60])
    sampled["HasExternalFormSubmit"] = 0
    sampled["Pay"] = 1
    sampled["Bank"] = rng.choice([0, 1], size=n_samples, p=[0.40, 0.60])
    sampled["Crypto"] = 0
    sampled["LetterRatioInURL"] = (sampled["NoOfLettersInURL"] / sampled["URLLength"]).round(6)
    sampled["DegitRatioInURL"] = (sampled["NoOfDegitsInURL"] / sampled["URLLength"]).round(6)
    doms, urls = _make_legit_domains(n_samples, chosen_tlds, rng, prefix="synth-shop-")
    sampled["Domain"] = doms
    sampled["URL"] = urls
    sampled["label"] = 1
    return sampled


def generate_scam_ecommerce_samples(base_phish: pd.DataFrame, n_samples: int = 16000, seed: int = 202) -> pd.DataFrame:
    """
    Generate diverse deceptive upfront-payment & unauthorized storefront/portal profiles:
    - Mixes obvious disposable-TLD scam shops AND stealthy HTTPS-enabled fake shopping /
      booking / brand-clone websites that mimic legitimate UX while exhibiting structural
      trust gaps (broken '#' links, external asset cloning, missing copyright/social, or
      brand impersonation).
    """
    rng = np.random.default_rng(seed)
    sampled = base_phish.sample(n=n_samples, replace=True, random_state=seed).copy().reset_index(drop=True)

    scam_tlds = ["shop", "store", "top", "xyz", "vip", "online", "club", "site", "cfd", "sbs", "icu", "buzz", "live", "com", "in", "co", "net"]
    t_probs = [0.09, 0.08, 0.07, 0.07, 0.05, 0.06, 0.05, 0.05, 0.04, 0.04, 0.04, 0.04, 0.04, 0.13, 0.08, 0.03, 0.04]
    chosen_tlds = rng.choice(scam_tlds, size=n_samples, p=t_probs)

    # Split into two scam archetypes:
    # 55% obvious scam templates, 45% stealthy HTTPS authorized-looking clones/non-delivery portals
    n_stealth = int(n_samples * 0.45)
    idx_stealth = sampled.index[:n_stealth]
    idx_tmpl = sampled.index[n_stealth:]

    sampled["TLD"] = chosen_tlds
    sampled["TLDLength"] = [len(t) for t in chosen_tlds]
    sampled["IsDomainIP"] = 0
    sampled["HasObfuscation"] = rng.choice([0, 1], size=n_samples, p=[0.85, 0.15])
    sampled["NoOfObfuscatedChar"] = np.where(sampled["HasObfuscation"] == 1, rng.integers(1, 8, size=n_samples), 0)
    sampled["NoOfSubDomain"] = rng.choice([0, 1, 2], size=n_samples, p=[0.50, 0.35, 0.15])
    sampled["DomainLength"] = rng.integers(14, 38, size=n_samples)
    sampled["URLLength"] = rng.integers(28, 120, size=n_samples)
    sampled["NoOfLettersInURL"] = (sampled["URLLength"] * rng.uniform(0.65, 0.84, size=n_samples)).astype(int)
    sampled["NoOfDegitsInURL"] = rng.integers(0, 8, size=n_samples)
    sampled["NoOfOtherSpecialCharsInURL"] = rng.integers(1, 7, size=n_samples)
    sampled["HasTitle"] = 1
    sampled["IsResponsive"] = 1
    sampled["HasSubmitButton"] = 1
    sampled["Pay"] = 1
    sampled["Bank"] = rng.choice([0, 1], size=n_samples, p=[0.35, 0.65])
    sampled["Crypto"] = rng.choice([0, 1], size=n_samples, p=[0.85, 0.15])

    # Archetype A: Stealthy HTTPS authorized-looking scam storefronts & portals
    sampled.loc[idx_stealth, "IsHTTPS"] = 1
    sampled.loc[idx_stealth, "LineOfCode"] = rng.integers(220, 1800, size=n_stealth)
    sampled.loc[idx_stealth, "LargestLineLength"] = rng.integers(500, 14000, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfImage"] = rng.integers(12, 85, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfCSS"] = rng.integers(2, 12, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfJS"] = rng.integers(2, 18, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfSelfRef"] = rng.integers(4, 24, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfExternalRef"] = rng.integers(8, 55, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfEmptyRef"] = rng.integers(3, 18, size=n_stealth)
    sampled.loc[idx_stealth, "NoOfiFrame"] = rng.choice([0, 1, 2], size=n_stealth, p=[0.60, 0.25, 0.15])
    sampled.loc[idx_stealth, "DomainTitleMatchScore"] = rng.choice([25.0, 50.0, 75.0, 100.0], size=n_stealth, p=[0.20, 0.30, 0.25, 0.25])
    sampled.loc[idx_stealth, "URLTitleMatchScore"] = sampled.loc[idx_stealth, "DomainTitleMatchScore"]
    sampled.loc[idx_stealth, "HasFavicon"] = rng.choice([0, 1], size=n_stealth, p=[0.25, 0.75])
    sampled.loc[idx_stealth, "HasDescription"] = rng.choice([0, 1], size=n_stealth, p=[0.50, 0.50])
    sampled.loc[idx_stealth, "HasSocialNet"] = rng.choice([0, 1], size=n_stealth, p=[0.80, 0.20])
    sampled.loc[idx_stealth, "HasCopyrightInfo"] = rng.choice([0, 1], size=n_stealth, p=[0.65, 0.35])
    sampled.loc[idx_stealth, "HasPasswordField"] = rng.choice([0, 1], size=n_stealth, p=[0.55, 0.45])
    sampled.loc[idx_stealth, "HasHiddenFields"] = rng.choice([0, 1], size=n_stealth, p=[0.35, 0.65])
    sampled.loc[idx_stealth, "HasExternalFormSubmit"] = rng.choice([0, 1], size=n_stealth, p=[0.70, 0.30])

    # Archetype B: Cloned template scam storefronts
    n_t = len(idx_tmpl)
    sampled.loc[idx_tmpl, "IsHTTPS"] = rng.choice([0, 1], size=n_t, p=[0.25, 0.75])
    sampled.loc[idx_tmpl, "LineOfCode"] = rng.integers(80, 750, size=n_t)
    sampled.loc[idx_tmpl, "LargestLineLength"] = rng.integers(300, 8000, size=n_t)
    sampled.loc[idx_tmpl, "NoOfImage"] = rng.integers(6, 48, size=n_t)
    sampled.loc[idx_tmpl, "NoOfCSS"] = rng.integers(1, 8, size=n_t)
    sampled.loc[idx_tmpl, "NoOfJS"] = rng.integers(1, 12, size=n_t)
    sampled.loc[idx_tmpl, "NoOfSelfRef"] = rng.integers(0, 9, size=n_t)
    sampled.loc[idx_tmpl, "NoOfExternalRef"] = rng.integers(12, 65, size=n_t)
    sampled.loc[idx_tmpl, "NoOfEmptyRef"] = rng.integers(4, 18, size=n_t)
    sampled.loc[idx_tmpl, "NoOfiFrame"] = rng.choice([0, 1, 2, 3], size=n_t, p=[0.45, 0.20, 0.25, 0.10])
    sampled.loc[idx_tmpl, "DomainTitleMatchScore"] = rng.choice([0.0, 10.0, 15.0], size=n_t, p=[0.65, 0.25, 0.10])
    sampled.loc[idx_tmpl, "URLTitleMatchScore"] = sampled.loc[idx_tmpl, "DomainTitleMatchScore"]
    sampled.loc[idx_tmpl, "HasFavicon"] = rng.choice([0, 1], size=n_t, p=[0.55, 0.45])
    sampled.loc[idx_tmpl, "HasDescription"] = rng.choice([0, 1], size=n_t, p=[0.70, 0.30])
    sampled.loc[idx_tmpl, "HasSocialNet"] = 0
    sampled.loc[idx_tmpl, "HasCopyrightInfo"] = rng.choice([0, 1], size=n_t, p=[0.75, 0.25])
    sampled.loc[idx_tmpl, "HasPasswordField"] = rng.choice([0, 1], size=n_t, p=[0.45, 0.55])
    sampled.loc[idx_tmpl, "HasHiddenFields"] = rng.choice([0, 1], size=n_t, p=[0.30, 0.70])
    sampled.loc[idx_tmpl, "HasExternalFormSubmit"] = rng.choice([0, 1], size=n_t, p=[0.45, 0.55])

    sampled["LetterRatioInURL"] = (sampled["NoOfLettersInURL"] / sampled["URLLength"]).round(6)
    sampled["DegitRatioInURL"] = (sampled["NoOfDegitsInURL"] / sampled["URLLength"]).round(6)
    sampled["ObfuscationRatio"] = (sampled["NoOfObfuscatedChar"] / sampled["URLLength"]).round(6)

    scam_stems = [
        "flipkart-mega-sale", "amazon-flash-deals", "myntra-outlet-offer",
        "meesho-discount-hub", "irctc-booking-portal", "bookmyshow-pass-deals",
        "trendybazaar", "megakart", "valuebazaar", "smartdealz", "flashmart",
    ]
    doms, urls = [], []
    for i, t in enumerate(chosen_tlds):
        stem = scam_stems[i % len(scam_stems)]
        dom = f"synth-scam-{stem}{i}.{t}"
        doms.append(dom)
        urls.append(f"https://{dom}/checkout" if sampled.loc[i, "IsHTTPS"] == 1 else f"http://{dom}/checkout")
    sampled["Domain"] = doms
    sampled["URL"] = urls
    sampled["label"] = 0
    return sampled


def main():
    print(f"Loading raw dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    cols = df.columns.tolist()
    print(f"Initial shape: {df.shape}")

    # Idempotently strip prior synthetic rows before regenerating
    if "Domain" in df.columns:
        df = df[~df["Domain"].astype(str).str.startswith(SYNTHETIC_DOMAIN_PREFIXES)].copy()

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

    # 3. Cap dead/empty 404 phishing stubs so lightweight valid pages aren't flagged
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

    # 4. Merge real live-discovered website vectors (both scam/unauthorized & legitimate commerce)
    if os.path.exists(LIVE_FEATURES_PATH):
        live_df = pd.read_csv(LIVE_FEATURES_PATH)
        # Re-align columns and upweight real live observations modestly so they shape splits
        live_df = live_df[[c for c in cols if c in live_df.columns]]
        if not live_df.empty:
            if "URL" in df_clean.columns and "URL" in live_df.columns:
                df_clean = df_clean[~df_clean["URL"].isin(live_df["URL"])].copy()
            live_df = pd.concat([live_df] * 6, ignore_index=True)
            print(f"Merged {len(live_df)} live-scraped real website profiles from {LIVE_FEATURES_PATH}.")
    else:
        print("Live discovered features file not found; scraping fallback valid URLs...")
        live_rows = [r for u in FALLBACK_LIVE_VALID_URLS if (r := extract_live_features(u, label=1))]
        live_df = pd.DataFrame(live_rows) if live_rows else pd.DataFrame(columns=cols)

    # 5. Augment modern valid webpages & deceptive scam/phishing webpages
    legit_pool = df_clean[df_clean["label"] == 1]
    phish_pool = df_clean[df_clean["label"] == 0]

    modern_valid_df = generate_modern_valid_samples(legit_pool, n_samples=35000, seed=42)
    active_phish_df = generate_active_phishing_samples(phish_pool, n_samples=15000, seed=99)
    valid_shop_df = generate_legitimate_ecommerce_samples(legit_pool, n_samples=12000, seed=123)
    scam_shop_df = generate_scam_ecommerce_samples(phish_pool, n_samples=16000, seed=202)

    final_df = pd.concat(
        [df_clean, live_df, modern_valid_df, active_phish_df, valid_shop_df, scam_shop_df],
        ignore_index=True,
    )
    final_df = final_df[cols].sample(frac=1.0, random_state=42).reset_index(drop=True)

    print("Final dataset shape:", final_df.shape)
    print("Final class distribution:\n", final_df["label"].value_counts())

    final_df.to_csv(DATASET_PATH, index=False)
    print(f"Saved cleaned & updated dataset to {DATASET_PATH}")


if __name__ == "__main__":
    main()
