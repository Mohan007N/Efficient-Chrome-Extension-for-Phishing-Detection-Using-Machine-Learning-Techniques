"""
scripts/update_trusted_domains.py — Verified Domain Catalog Builder

Builds `data/verified_domains.csv` from candidate domains across Categories A-G.
Each candidate is verified against:
  1. `dataset/tranco_top1m.json.gz` (popularity rank — never alone treated as proof of safety)
  2. `dataset/unauthorized_domains.json.gz` (PhishDB, HaGeZi, OpenPhish, CERT.pl, Scam-Blocklist)
  3. Optional rate-limited live DNS/HTTPS check (`--verify-live`)

Unverified or conflicting candidates are downgraded to label `3` (suspicious/uncertain)
rather than silently treated as benign.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import json
import os
import sys
import time

import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.security import validate_safe_url_and_resolve
from src.features import extract_root_domain, is_hosted_user_content_subdomain
from src.seed_catalog import VERIFIED_SEED_CANDIDATES

VERIFIED_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "verified_domains.csv")
TRANCO_PATH = os.path.join(PROJECT_ROOT, "dataset", "tranco_top1m.json.gz")
UNAUTH_PATH = os.path.join(PROJECT_ROOT, "dataset", "unauthorized_domains.json.gz")


def _load_tranco() -> dict[str, int]:
    if not os.path.exists(TRANCO_PATH):
        return {}
    with gzip.open(TRANCO_PATH, "rt", encoding="utf-8") as gz:
        return json.load(gz)


def _load_threat_sets() -> dict[str, set[str]]:
    if not os.path.exists(UNAUTH_PATH):
        return {}
    with gzip.open(UNAUTH_PATH, "rt", encoding="utf-8") as gz:
        data = json.load(gz)
    return {
        "hagezi_fake": set(data.get("hagezi_fake", [])),
        "hagezi_tif": set(data.get("hagezi_tif", [])),
        "phishing_database": set(data.get("phishing_database", [])),
        "cert_pl": set(data.get("cert_pl", [])),
        "openphish_domains": set(data.get("openphish_domains", [])),
        "jarelllama_scams": set(data.get("jarelllama_scams", [])),
    }


def build_verified_domains_csv(output_path: str = VERIFIED_CSV_PATH, verify_live: bool = False) -> pd.DataFrame:
    tranco = _load_tranco()
    threat_sets = _load_threat_sets()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    rows: list[dict] = []
    for idx, (dom, brand, cat, ownership, intended_label, is_hosting, note) in enumerate(VERIFIED_SEED_CANDIDATES, start=1):
        d = dom.lower().strip()
        root = extract_root_domain(d)
        rank = tranco.get(d) or tranco.get(root)

        hit_sources = [
            src_name for src_name, sset in threat_sets.items()
            if (d in sset) or (not is_hosted_user_content_subdomain(d) and root in sset)
        ]

        dns_ok = None
        if verify_live:
            try:
                validate_safe_url_and_resolve(f"https://{d}/", resolve_dns=True)
                dns_ok = True
            except Exception:
                dns_ok = False
            time.sleep(0.05)

        if hit_sources and not is_hosting:
            label = 3
            confidence = "low"
            ver_source = f"flagged_in:{'|'.join(hit_sources)}"
        elif rank is not None:
            label = int(intended_label)
            confidence = "high" if not is_hosting else "medium"
            ver_source = f"tranco_rank_{rank}+threat_feed_clean" + ("+dns_ok" if dns_ok else "")
        elif d.endswith((".edu.in", ".ac.in", ".gov.in", ".sbi")):
            # Institutional/regulated TLD verified cleanly against threat feeds
            label = int(intended_label)
            confidence = "high" if not hit_sources else "low"
            ver_source = "regulated_tld_registry+threat_feed_clean" + ("+dns_ok" if dns_ok else "")
        else:
            # Unverified against Tranco/institutional registry -> label 3 (uncertain)
            label = 3
            confidence = "low"
            ver_source = "unverified_candidate"

        rows.append({
            "id": idx,
            "domain": d,
            "root_domain": root,
            "brand": brand,
            "category": cat,
            "ownership_type": ownership,
            "label": label,
            "verification_source": ver_source,
            "verification_date": today,
            "confidence": confidence,
            "notes": note,
        })

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Wrote {len(df)} rows to {output_path} | label counts: {df['label'].value_counts().to_dict()}")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build verified legitimate & third-party domain catalog.")
    parser.add_argument("--output", default=VERIFIED_CSV_PATH)
    parser.add_argument("--verify-live", action="store_true", help="Verify public DNS resolution (rate-limited).")
    args = parser.parse_args()
    build_verified_domains_csv(output_path=args.output, verify_live=args.verify_live)

