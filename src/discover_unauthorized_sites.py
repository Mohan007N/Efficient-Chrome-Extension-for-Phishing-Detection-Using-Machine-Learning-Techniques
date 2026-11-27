"""
src/discover_unauthorized_sites.py — Real-World Unauthorized & Scam Website Discovery Pipeline

Discovers active unauthorized, fraudulent, fake-shopping, and deceptive upfront-payment
websites (sites that look HTTPS-secured and legitimate on the surface, evading firewalls)
from public threat & fake-shop feeds + verified non-delivery/scam registries + live probing.

Outputs (saved in dataset/):
  - unauthorized_domains.json.gz     (O(1) domain index for backend intel)
  - tranco_top1m.json.gz             (Top-1M authority rank lookup)
  - discovered_unauthorized_sites.csv (Human-readable catalog of discovered scam/unauthorized URLs)
  - live_discovered_features.csv     (Live-scraped 55-col PhiUSIIL features + forensic risk flags)
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import gzip
import io
import json
import os
import sys
import zipfile
from urllib.parse import urlparse

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.features import TRUSTED_DOMAINS, detect_brand_impersonation, extract_root_domain
from src.web_forensics import (
    analyze_storefront_forensics,
    extract_phiusiil_features_from_html,
    fetch_url_bytes,
    fetch_url_html,
)

DATASET_DIR = "dataset"
UNAUTHORIZED_INDEX_PATH = os.path.join(DATASET_DIR, "unauthorized_domains.json.gz")
TRANCO_INDEX_PATH = os.path.join(DATASET_DIR, "tranco_top1m.json.gz")
DISCOVERED_CATALOG_PATH = os.path.join(DATASET_DIR, "discovered_unauthorized_sites.csv")
LIVE_FEATURES_PATH = os.path.join(DATASET_DIR, "live_discovered_features.csv")

THREAT_FEEDS = {
    "hagezi_fake": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "jarelllama_scams": "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt",
    "openphish": "https://openphish.com/feed.txt",
}
TRANCO_FEED_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Verified documented deceptive upfront-payment, non-delivery & unauthorized commerce/portal sites.
# Note: Only verified high-complaint / confirmed scam domains belong here (never legitimate stores).
VERIFIED_UNAUTHORIZED_SITES: dict[str, dict] = {
    "vlebazaar.in": {
        "url": "https://vlebazaar.in/",
        "category": "upfront_payment_scam_store",
        "source": "verified_consumer_fraud_registry",
        "reason": "High-volume non-delivery & prepaid order scam complaints; missing corporate GSTIN/email, store-credit refund trap, WhatsApp-only support.",
    },
}

# Authentic legitimate shopping, booking, courier, banking & developer portals for live baseline extraction
VERIFIED_LEGITIMATE_URLS: list[str] = [
    "https://www.flipkart.com/",
    "https://www.myntra.com/",
    "https://www.ajio.com/",
    "https://www.nykaa.com/",
    "https://www.tatacliq.com/",
    "https://www.croma.com/",
    "https://www.reliancedigital.in/",
    "https://www.vijaysales.com/",
    "https://www.jiomart.com/",
    "https://www.meesho.com/",
    "https://www.bigbasket.com/",
    "https://www.snapdeal.com/",
    "https://www.lenskart.com/",
    "https://www.firstcry.com/",
    "https://www.pepperfry.com/",
    "https://www.decathlon.in/",
    "https://www.makemytrip.com/",
    "https://www.goibibo.com/",
    "https://www.cleartrip.com/",
    "https://in.bookmyshow.com/",
    "https://www.redbus.in/",
    "https://www.zomato.com/",
    "https://www.swiggy.com/",
    "https://paytm.com/",
    "https://www.phonepe.com/",
    "https://razorpay.com/",
    "https://www.hdfcbank.com/",
    "https://www.icicibank.com/",
    "https://www.delhivery.com/",
    "https://www.bluedart.com/",
    "https://www.apple.com/",
    "https://www.samsung.com/in/",
    "https://www.nike.com/",
    "https://www.shopify.com/",
    "https://www.target.com/",
    "https://www.ikea.com/",
    "https://www.ebay.com/",
    "https://www.etsy.com/",
    "https://docs.python.org/3/library/os.html",
    "https://docs.python.org/3/tutorial/index.html",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/explore",
    "https://stackoverflow.com/questions",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://scikit-learn.org/stable/user_guide.html",
    "https://pandas.pydata.org/docs/getting_started/index.html",
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
    "https://letsencrypt.org/getting-started/",
    "https://owasp.org/www-project-top-ten/",
    "https://www.nist.gov/cyberframework",
    "https://example.com/",
    "https://example.org/",
]


def _is_trusted_or_official(domain: str) -> bool:
    root = extract_root_domain(domain)
    return domain in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS


def fetch_tranco_ranks(timeout: float = 20.0) -> dict[str, int]:
    """Download and parse Tranco Top-1M CSV zip into a domain->rank dictionary."""
    print("Fetching Tranco Top-1M authority list...")
    _, _, raw_zip = fetch_url_bytes(TRANCO_FEED_URL, timeout=timeout, max_bytes=25_000_000)
    ranks: dict[str, int] = {}
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        csv_name = zf.namelist()[0]
        with zf.open(csv_name) as f:
            for line_b in f:
                line = line_b.decode("utf-8", errors="ignore").strip()
                if "," in line:
                    r_str, dom = line.split(",", 1)
                    if r_str.isdigit():
                        ranks[dom.strip().lower()] = int(r_str)
    print(f"Loaded {len(ranks):,} Tranco ranked domains.")
    return ranks


def fetch_threat_feeds(timeout: float = 20.0) -> dict[str, object]:
    """Fetch HaGeZi Fake, jarelllama Scam-Blocklist, and OpenPhish feeds."""
    results: dict[str, object] = {
        "hagezi_fake": [],
        "jarelllama_scams": [],
        "openphish_urls": [],
        "openphish_domains": [],
    }

    for key, feed_url in THREAT_FEEDS.items():
        try:
            print(f"Fetching feed '{key}' from {feed_url}...")
            _, _, raw = fetch_url_bytes(feed_url, timeout=timeout, max_bytes=30_000_000)
            text = raw.decode("utf-8", errors="ignore")
            lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith(("#", "!"))]

            if key == "openphish":
                clean_urls = []
                op_domains = set()
                for u in lines:
                    host = (urlparse(u).hostname or "").lower()
                    if host and not _is_trusted_or_official(host):
                        clean_urls.append(u)
                        op_domains.add(host)
                results["openphish_urls"] = clean_urls
                results["openphish_domains"] = sorted(op_domains)
                print(f"  -> {len(clean_urls):,} active URLs ({len(op_domains):,} domains)")
            else:
                doms = []
                for d in lines:
                    d_clean = d.lstrip("*.").lower()
                    if "." in d_clean and not _is_trusted_or_official(d_clean):
                        doms.append(d_clean)
                results[key] = sorted(set(doms))
                print(f"  -> {len(results[key]):,} domains")
        except Exception as e:
            print(f"  [WARN] Failed to fetch {key}: {e}")

    return results


def _probe_single_target(item: tuple[str, int, str, str]) -> tuple[dict | None, dict]:
    """
    Probe one live URL to extract its 55-column PhiUSIIL features and storefront forensics.
    item = (url, label, category, source)
    """
    url, label, category, source = item
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    catalog_entry = {
        "domain": host,
        "root_domain": extract_root_domain(host),
        "url": url,
        "label": label,
        "category": category,
        "source": source,
        "is_live": False,
        "is_https": 1 if parsed.scheme == "https" else 0,
        "forensic_risk_score": 0.0,
        "forensic_flags": "",
    }

    try:
        final_url, status, html = fetch_url_html(url, timeout=5.5, max_bytes=350_000)
        if status >= 400 or len(html) < 250:
            return None, catalog_entry

        feat = extract_phiusiil_features_from_html(final_url or url, html, label=label)
        if not feat:
            return None, catalog_entry

        forensics = analyze_storefront_forensics(
            final_url or url,
            html,
            follow_policy_pages=(label == 0),
            timeout=2.0,
        )
        catalog_entry["is_live"] = True
        catalog_entry["url"] = final_url or url
        catalog_entry["is_https"] = feat["IsHTTPS"]
        catalog_entry["forensic_risk_score"] = forensics["forensic_risk_score"]
        catalog_entry["forensic_flags"] = " | ".join(forensics["forensic_flags"])
        return feat, catalog_entry
    except Exception:
        return None, catalog_entry


def build_probe_targets(feeds: dict, max_hagezi: int = 160, max_openphish: int = 80, max_scam_kw: int = 80) -> list[tuple[str, int, str, str]]:
    """Select high-value unauthorized storefront, brand-impersonation, and legitimate targets for live scraping."""
    targets: list[tuple[str, int, str, str]] = []
    seen_hosts: set[str] = set()

    # 1. Always include verified upfront-payment scam sites (e.g. vlebazaar.in)
    for dom, meta in VERIFIED_UNAUTHORIZED_SITES.items():
        seen_hosts.add(dom)
        targets.append((meta["url"], 0, meta["category"], meta["source"]))

    # 2. Sample fake-shop / scam domains from HaGeZi Fake
    hagezi_doms: list[str] = feeds.get("hagezi_fake", [])
    # Prioritize commerce/shop/pay/store-looking domains first so we get rich fake-store training vectors
    commerce_hints = ("shop", "store", "mart", "deal", "buy", "outlet", "mall", "market", "kart", "pay", "sale", "fashion", "tech")
    hagezi_prioritized = sorted(
        hagezi_doms,
        key=lambda d: (0 if any(h in d for h in commerce_hints) else 1, len(d)),
    )
    for d in hagezi_prioritized[:max_hagezi]:
        if d not in seen_hosts:
            seen_hosts.add(d)
            targets.append((f"https://{d}/", 0, "fake_shop_or_scam", "hagezi_fake"))

    # 3. Sample active HTTPS phishing / portal URLs from OpenPhish
    for u in feeds.get("openphish_urls", [])[:max_openphish]:
        h = (urlparse(u).hostname or "").lower()
        if h and h not in seen_hosts:
            seen_hosts.add(h)
            targets.append((u, 0, "active_phish_portal", "openphish"))

    # 4. Sample brand-impersonating or commerce-scam domains from jarelllama Scam-Blocklist
    scam_doms: list[str] = feeds.get("jarelllama_scams", [])
    impersonators = []
    for d in scam_doms:
        if d in seen_hosts:
            continue
        imp_score, _ = detect_brand_impersonation(d)
        if imp_score >= 0.80 or any(k in d for k in ("shop", "store", "flipkart", "amazon", "paytm", "irctc", "booking", "bazaar")):
            impersonators.append(d)
        if len(impersonators) >= max_scam_kw:
            break
    for d in impersonators:
        seen_hosts.add(d)
        targets.append((f"https://{d}/", 0, "brand_impersonation_scam", "jarelllama_scams"))

    # 5. Legitimate shopping, booking, banking, and portal targets (label = 1)
    for u in VERIFIED_LEGITIMATE_URLS:
        h = (urlparse(u).hostname or "").lower()
        targets.append((u, 1, "verified_legitimate", "curated_authorized"))

    return targets


def discover_and_build(probe_live: bool = True, max_workers: int = 16) -> dict:
    """Run full discovery pipeline, build compressed backend indexes, catalog CSV, and live features CSV."""
    os.makedirs(DATASET_DIR, exist_ok=True)

    tranco_ranks = {}
    try:
        tranco_ranks = fetch_tranco_ranks()
        with gzip.open(TRANCO_INDEX_PATH, "wt", encoding="utf-8") as gz:
            json.dump(tranco_ranks, gz)
        print(f"Saved Tranco rank index -> {TRANCO_INDEX_PATH}")
    except Exception as e:
        print(f"[WARN] Could not refresh Tranco index: {e}")
        if os.path.exists(TRANCO_INDEX_PATH):
            with gzip.open(TRANCO_INDEX_PATH, "rt", encoding="utf-8") as gz:
                tranco_ranks = json.load(gz)

    feeds = fetch_threat_feeds()

    # Build fast backend unauthorized-domain index (exclude any trusted domains)
    index_payload = {
        "verified": VERIFIED_UNAUTHORIZED_SITES,
        "hagezi_fake": feeds.get("hagezi_fake", []),
        "openphish_domains": feeds.get("openphish_domains", []),
        "jarelllama_scams": feeds.get("jarelllama_scams", []),
    }
    with gzip.open(UNAUTHORIZED_INDEX_PATH, "wt", encoding="utf-8") as gz:
        json.dump(index_payload, gz)
    print(f"Saved compressed unauthorized domain index -> {UNAUTHORIZED_INDEX_PATH}")

    # Build human-readable catalog of discovered unauthorized websites
    catalog_rows: list[dict] = []
    seen_catalog: set[str] = set()

    def _add_catalog_row(dom: str, url: str, category: str, source: str, reason: str, is_live: bool = False, risk: float = 0.0, flags: str = ""):
        if not dom or dom in seen_catalog or _is_trusted_or_official(dom):
            return
        seen_catalog.add(dom)
        root = extract_root_domain(dom)
        catalog_rows.append({
            "domain": dom,
            "root_domain": root,
            "url": url,
            "category": category,
            "source": source,
            "tranco_rank": tranco_ranks.get(root) or tranco_ranks.get(dom),
            "is_live": is_live,
            "forensic_risk_score": risk,
            "reason": flags or reason,
        })

    for dom, meta in VERIFIED_UNAUTHORIZED_SITES.items():
        _add_catalog_row(dom, meta["url"], meta["category"], meta["source"], meta["reason"])

    live_feature_rows: list[dict] = []
    if probe_live:
        targets = build_probe_targets(feeds)
        print(f"Concurrently probing {len(targets)} live URLs (max_workers={max_workers})...")
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = [pool.submit(_probe_single_target, t) for t in targets]
            for fut in as_completed(futs):
                feat, cat = fut.result()
                if feat:
                    live_feature_rows.append(feat)
                if cat["label"] == 0:
                    _add_catalog_row(
                        cat["domain"],
                        cat["url"],
                        cat["category"],
                        cat["source"],
                        f"Discovered via {cat['source']} ({cat['category']})",
                        is_live=cat["is_live"],
                        risk=cat["forensic_risk_score"],
                        flags=cat["forensic_flags"],
                    )

        if live_feature_rows:
            live_df = pd.DataFrame(live_feature_rows)
            live_df.to_csv(LIVE_FEATURES_PATH, index=False)
            n_scam_live = int((live_df["label"] == 0).sum())
            n_legit_live = int((live_df["label"] == 1).sum())
            print(f"Saved {len(live_df)} live feature vectors (scam/unauthorized={n_scam_live}, legitimate={n_legit_live}) -> {LIVE_FEATURES_PATH}")

    # Append remaining HaGeZi Fake, OpenPhish, and brand-impersonating scam domains to the catalog CSV (capped for readability)
    for d in feeds.get("hagezi_fake", []):
        _add_catalog_row(d, f"https://{d}/", "fake_shop_or_scam", "hagezi_fake", "Flagged in HaGeZi Fake/Scam storefront blocklist.")
    for u in feeds.get("openphish_urls", []):
        h = (urlparse(u).hostname or "").lower()
        _add_catalog_row(h, u, "active_phish_portal", "openphish", "Active phishing/deceptive portal in OpenPhish feed.")

    brand_scams_added = 0
    for d in feeds.get("jarelllama_scams", []):
        imp, brand = detect_brand_impersonation(d)
        if imp >= 0.80 or any(k in d for k in ("shop", "store", "kart", "bazaar", "deal", "pay", "bank", "booking")):
            reason = f"Impersonates '{brand}' on unauthorized domain." if brand else "Commerce/portal scam pattern in Scam-Blocklist."
            _add_catalog_row(d, f"https://{d}/", "scam_commerce_or_clone", "jarelllama_scams", reason)
            brand_scams_added += 1
            if brand_scams_added >= 10000:
                break

    catalog_df = pd.DataFrame(catalog_rows)
    catalog_df.to_csv(DISCOVERED_CATALOG_PATH, index=False)
    print(f"Saved catalog of {len(catalog_df):,} discovered unauthorized websites -> {DISCOVERED_CATALOG_PATH}")

    return {
        "tranco_count": len(tranco_ranks),
        "hagezi_fake_count": len(feeds.get("hagezi_fake", [])),
        "jarelllama_scams_count": len(feeds.get("jarelllama_scams", [])),
        "openphish_count": len(feeds.get("openphish_urls", [])),
        "live_scraped_count": len(live_feature_rows),
        "catalog_count": len(catalog_df),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Discover real-world unauthorized and scam websites.")
    parser.add_argument("--no-probe", action="store_true", help="Skip live HTTP probing of domains.")
    parser.add_argument("--workers", type=int, default=16, help="Thread count for live probing.")
    args = parser.parse_args()
    summary = discover_and_build(probe_live=not args.no_probe, max_workers=args.workers)
    print("Discovery Summary:", json.dumps(summary, indent=2))

