"""
scripts/deduplicate_dataset.py — Deterministic URL Normalization & Conflict-Aware Deduplication
"""

from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.dataset_validation import detect_conflicting_labels
from src.features import extract_root_domain, normalize_url


def deduplicate_csv(input_path: str, output_path: str | None = None) -> dict:
    df = pd.read_csv(input_path)
    before = len(df)
    if "url" in df.columns:
        df["url"] = df["url"].fillna("").astype(str).map(normalize_url)
    elif "normalized_url" in df.columns:
        df["normalized_url"] = df["normalized_url"].fillna("").astype(str).map(normalize_url)

    url_col = "url" if "url" in df.columns else "normalized_url"
    if "binary_label" in df.columns:
        clean_df, stats = detect_conflicting_labels(df.rename(columns={url_col: "url"}))
        if url_col != "url":
            clean_df = clean_df.rename(columns={"url": url_col})
    else:
        clean_df = df.drop_duplicates(subset=[url_col], keep="first").reset_index(drop=True)
        stats = {"conflicting_url_count": 0, "exact_duplicate_url_count": before - len(clean_df)}

    if "root_domain" in clean_df.columns and url_col in clean_df.columns:
        missing_root = clean_df["root_domain"].isna() | (clean_df["root_domain"].astype(str).str.strip() == "")
        if missing_root.any():
            clean_df.loc[missing_root, "root_domain"] = clean_df.loc[missing_root, url_col].map(
                lambda u: extract_root_domain(u.split("://", 1)[-1].split("/", 1)[0])
            )

    target = output_path or input_path
    clean_df.to_csv(target, index=False)
    return {"before": before, "after": len(clean_df), "removed": before - len(clean_df), **stats}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize and deduplicate a dataset CSV.")
    parser.add_argument("input_csv", help="Path to CSV file.")
    parser.add_argument("--output", default=None, help="Optional output CSV path (defaults to in-place).")
    args = parser.parse_args()
    print(deduplicate_csv(args.input_csv, args.output))

