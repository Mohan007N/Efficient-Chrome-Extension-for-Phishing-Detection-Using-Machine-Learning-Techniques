"""
scripts/build_training_dataset.py — Controlled Multi-Source Dataset Orchestrator

Executes:
  1. `scripts/update_trusted_domains.py` -> `data/verified_domains.csv`
  2. `scripts/update_threat_feeds.py` -> `data/phishing_domains.csv` & `data/synthetic_lookalikes.csv`
  3. `src/build_datasets.py` -> 5-class `multiclass_dataset.csv`, domain-disjoint `url_*` & `dom_*` splits
  4. `scripts/validate_dataset.py` -> schema, leakage & 5-class label integrity verification
"""

from __future__ import annotations

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from scripts.update_threat_feeds import update_phishing_and_lookalike_datasets
from scripts.update_trusted_domains import build_verified_domains_csv
from scripts.validate_dataset import validate_all_datasets
from src.build_datasets import build_all_datasets


def main():
    parser = argparse.ArgumentParser(description="Build verified, phishing, multiclass, and ML training datasets.")
    parser.add_argument("--max-phiusiil", type=int, default=60000)
    parser.add_argument("--max-phreshphish", type=int, default=6000)
    parser.add_argument("--fetch-live", action="store_true", help="Fetch live OpenPhish & DNS checks.")
    args = parser.parse_args()

    print("[1/4] Building verified domain catalog (data/verified_domains.csv)...")
    build_verified_domains_csv(verify_live=args.fetch_live)

    print("[2/4] Updating phishing & lookalike catalogs (data/phishing_domains.csv)...")
    update_phishing_and_lookalike_datasets(fetch_live=args.fetch_live)

    print("[3/4] Building 5-class & domain-disjoint ML datasets (data/processed/)...")
    build_all_datasets(
        max_phiusiil=args.max_phiusiil,
        max_phreshphish=args.max_phreshphish,
        refresh_phreshphish=False,
    )

    print("[4/4] Validating schemas and domain-disjoint partitions...")
    res = validate_all_datasets()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

