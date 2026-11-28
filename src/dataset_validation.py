"""
src/dataset_validation.py — Schema Validation, Data Quality Auditing & Leakage Prevention (v3.0)

Ensures:
1. Strict separation between ML classification labels (`0=Phishing/Malicious`, `1=Benign/Legitimate`,
   `-1=Non-binary/Operational`) and `operational_status` (`Malicious`, `Benign`, `Unknown`,
   `Unreachable`, `Blocked`, `Insufficient evidence`).
2. Consistent URL & DOM provenance, conflict resolution, missing/duplicate/outlier analysis,
   and `reports/v3_dataset_quality_report.md` generation.
3. Domain-grouped train/validation/test splits (`GroupShuffleSplit` on PSL `root_domain`) with
   zero domain overlap across partitions + chronological temporal split verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

RISK_CATEGORIES: tuple[str, ...] = (
    "benign",
    "phishing",
    "brand_impersonation",
    "malware_distribution",
    "credential_risk",
    "payment_risk",
    "deceptive_behavior",
    "suspicious_redirect",
    "unknown",
)

OPERATIONAL_STATUSES: tuple[str, ...] = (
    "Malicious",
    "Benign",
    "Unknown",
    "Unreachable",
    "Blocked",
    "Insufficient evidence",
)

URL_TAXONOMY_CATEGORIES: tuple[str, ...] = (
    "http_legitimate",
    "https_legitimate",
    "http_phishing",
    "https_phishing",
    "brand_impersonation",
    "typosquatting",
    "homoglyph",
    "punycode",
    "ip_based_phishing",
    "suspicious_subdomain",
    "url_shortener",
    "fake_login",
    "fake_banking",
    "fake_ecommerce",
    "fake_payment",
    "compromised_legitimate",
    "firewall_blocked",
    "unknown_unreachable",
)

PROVENANCE_COLUMNS: tuple[str, ...] = (
    "url",
    "domain",
    "root_domain",
    "source",
    "collection_timestamp",
    "collection_method",
    "feature_extraction_version",
    "content_sha256",
    "verification_status",
    "operational_status",
    "threat_category",
    "html_available",
    "primary_label",
    "risk_labels",
    "confidence",
    "evidence",
)

FORBIDDEN_CREDENTIAL_COLUMNS = {"password", "passwd", "cookie", "cookies", "token", "auth_token", "secret"}


def validate_dataset_schema(df: pd.DataFrame, required_columns: list[str], allow_empty: bool = False) -> dict:
    """Validate dataset integrity, forbidden credential fields, labels, and required columns."""
    if df is None or (df.empty and not allow_empty):
        raise ValueError("Dataset DataFrame is empty.")

    lower_cols = {c.lower() for c in df.columns}
    forbidden_found = lower_cols.intersection(FORBIDDEN_CREDENTIAL_COLUMNS)
    if forbidden_found:
        raise ValueError(f"Privacy violation: forbidden credential columns present: {sorted(forbidden_found)}")

    missing = [c for c in required_columns if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    if "primary_label" in df.columns:
        unknown_labels = set(df["primary_label"].dropna().astype(str)) - set(RISK_CATEGORIES)
        if unknown_labels:
            raise ValueError(f"Unsupported primary_label values found: {sorted(unknown_labels)}")

    if "operational_status" in df.columns:
        unknown_ops = set(df["operational_status"].dropna().astype(str)) - set(OPERATIONAL_STATUSES)
        if unknown_ops:
            raise ValueError(f"Unsupported operational_status values found: {sorted(unknown_ops)}")

    if "binary_label" in df.columns:
        bad_bin = set(pd.to_numeric(df["binary_label"], errors="coerce").dropna().astype(int)) - {0, 1, -1}
        if bad_bin:
            raise ValueError(f"Unsupported binary_label values found: {sorted(bad_bin)}")

    return {
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "null_cells": int(df.isnull().sum().sum()),
        "duplicate_urls": int(df["url"].duplicated().sum()) if "url" in df.columns else 0,
        "unique_root_domains": int(df["root_domain"].nunique()) if "root_domain" in df.columns else 0,
    }


def verify_domain_disjoint(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame | None = None,
    test_df: pd.DataFrame | None = None,
    group_col: str = "root_domain",
) -> bool:
    """Verify zero domain overlap across train, validation, and test partitions."""
    train_domains = set(train_df[group_col].dropna().astype(str).str.lower())
    if val_df is not None and not val_df.empty:
        val_domains = set(val_df[group_col].dropna().astype(str).str.lower())
        overlap_tv = train_domains.intersection(val_domains)
        if overlap_tv:
            raise AssertionError(f"Domain leakage between train and val: {len(overlap_tv)} overlapping domains")
    if test_df is not None and not test_df.empty:
        test_domains = set(test_df[group_col].dropna().astype(str).str.lower())
        overlap_tt = train_domains.intersection(test_domains)
        if overlap_tt:
            raise AssertionError(f"Domain leakage between train and test: {len(overlap_tt)} overlapping domains")
        if val_df is not None and not val_df.empty:
            val_domains = set(val_df[group_col].dropna().astype(str).str.lower())
            overlap_vt = val_domains.intersection(test_domains)
            if overlap_vt:
                raise AssertionError(f"Domain leakage between val and test: {len(overlap_vt)} overlapping domains")
    return True


def domain_grouped_train_val_test_split(
    df: pd.DataFrame,
    group_col: str = "root_domain",
    test_size: float = 0.20,
    val_size: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split verified binary records into strictly domain-disjoint train, validation, and test partitions
    using GroupShuffleSplit on `root_domain`.
    """
    if group_col not in df.columns:
        raise ValueError(f"Missing grouping column '{group_col}' for domain-grouped split.")

    groups = df[group_col].fillna("unknown").astype(str).str.lower()
    gss_test = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_val_idx, test_idx = next(gss_test.split(df, groups=groups))

    train_val_df = df.iloc[train_val_idx].reset_index(drop=True)
    test_df = df.iloc[test_idx].reset_index(drop=True)

    rel_val_size = val_size / max(1e-6, (1.0 - test_size))
    tv_groups = train_val_df[group_col].fillna("unknown").astype(str).str.lower()
    gss_val = GroupShuffleSplit(n_splits=1, test_size=rel_val_size, random_state=random_state + 1)
    train_idx, val_idx = next(gss_val.split(train_val_df, groups=tv_groups))

    train_df = train_val_df.iloc[train_idx].reset_index(drop=True)
    val_df = train_val_df.iloc[val_idx].reset_index(drop=True)

    verify_domain_disjoint(train_df, val_df, test_df, group_col=group_col)
    return train_df, val_df, test_df


def temporal_train_test_split(
    df: pd.DataFrame,
    date_col: str = "date",
    test_fraction: float = 0.25,
    group_col: str = "root_domain",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Chronologically split timestamped data (earlier -> train, later -> test),
    removing any overlapping test domains from training to keep evaluation leakage-free.
    """
    dated = df[df[date_col].notna()].copy()
    if dated.empty:
        raise ValueError(f"No valid timestamps in '{date_col}' for temporal split.")
    dated["_parsed_dt"] = pd.to_datetime(dated[date_col], errors="coerce")
    dated = dated[dated["_parsed_dt"].notna()].sort_values("_parsed_dt").reset_index(drop=True)
    split_pos = max(1, int(len(dated) * (1.0 - test_fraction)))
    train_df = dated.iloc[:split_pos].drop(columns=["_parsed_dt"]).reset_index(drop=True)
    test_df = dated.iloc[split_pos:].drop(columns=["_parsed_dt"]).reset_index(drop=True)

    if group_col in dated.columns:
        test_domains = set(test_df[group_col].dropna().astype(str).str.lower())
        train_df = train_df[~train_df[group_col].astype(str).str.lower().isin(test_domains)].reset_index(drop=True)
        verify_domain_disjoint(train_df, test_df=test_df, group_col=group_col)
    return train_df, test_df


def _near_duplicate_key(url: str) -> str:
    p = urlparse(str(url or ""))
    return f"{(p.hostname or '').lower()}{(p.path or '/').rstrip('/') or '/'}"


def detect_conflicting_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """
    Detect and cleanly resolve conflicting binary labels across identical normalized URLs.
    Malicious verified evidence (`0`) takes conservative precedence over benign (`1`).
    """
    if df.empty or "url" not in df.columns or "binary_label" not in df.columns:
        return df, {"conflicting_url_count": 0, "exact_duplicate_url_count": 0}

    exact_dups = int(df["url"].duplicated().sum())
    grp = df.groupby("url")["binary_label"].nunique()
    conflicting_urls = grp[grp > 1].index.tolist()

    # Conservative deterministic priority: label 0 (verified threat) > label 1, higher confidence
    ordered = df.sort_values(by=["binary_label", "confidence"], ascending=[True, False], kind="mergesort")
    dedup = ordered.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    return dedup, {
        "conflicting_url_count": len(conflicting_urls),
        "exact_duplicate_url_count": exact_dups,
        "conflicting_examples": conflicting_urls[:5],
    }


def _numeric_outlier_summary(df: pd.DataFrame, cols: list[str], top_n: int = 10) -> list[dict]:
    rows = []
    for col in cols:
        if col not in df.columns or not pd.api.types.is_numeric_dtype(df[col]):
            continue
        s = pd.to_numeric(df[col], errors="coerce").dropna()
        if s.empty:
            continue
        q1, q3 = float(s.quantile(0.25)), float(s.quantile(0.75))
        iqr = q3 - q1
        upper = q3 + 3.0 * iqr
        n_out = int((s > upper).sum()) if iqr > 0 else 0
        rows.append({
            "feature": col,
            "mean": round(float(s.mean()), 4),
            "median": round(float(s.median()), 4),
            "max": round(float(s.max()), 4),
            "extreme_outliers_3iqr": n_out,
        })
    rows.sort(key=lambda r: r["extreme_outliers_3iqr"], reverse=True)
    return rows[:top_n]


def run_dataset_quality_audit(
    combined_df: pd.DataFrame,
    url_df: pd.DataFrame,
    dom_df: pd.DataFrame,
    uncertain_df: pd.DataFrame,
    operational_df: pd.DataFrame,
    url_splits: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame],
    dom_splits: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame],
    conflict_stats: dict,
    url_feature_cols: list[str],
    dom_feature_cols: list[str],
    report_path: str = os.path.join("reports", "v3_dataset_quality_report.md"),
) -> dict:
    """Run Phase 4.1 validation checks and write `reports/v3_dataset_quality_report.md`."""
    u_tr, u_va, u_te = url_splits
    d_tr, d_va, d_te = dom_splits
    verify_domain_disjoint(u_tr, u_va, u_te, group_col="root_domain")
    verify_domain_disjoint(d_tr, d_va, d_te, group_col="root_domain")

    near_dups_url = int(url_df["url"].map(_near_duplicate_key).duplicated().sum()) if not url_df.empty else 0
    near_dups_dom = int(dom_df["url"].map(_near_duplicate_key).duplicated().sum()) if not dom_df.empty else 0

    parsed_dates = pd.to_datetime(combined_df.get("date"), errors="coerce") if "date" in combined_df.columns else pd.Series(dtype="datetime64[ns]")
    valid_dates = parsed_dates.dropna()

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "combined_rows": int(len(combined_df)),
        "url_rows": int(len(url_df)),
        "dom_rows": int(len(dom_df)),
        "uncertain_rows": int(len(uncertain_df)),
        "operational_quarantined_rows": int(len(operational_df)),
        "url_missing_cells": int(url_df.isnull().sum().sum()),
        "dom_missing_cells": int(dom_df.isnull().sum().sum()),
        "url_near_duplicate_paths": near_dups_url,
        "dom_near_duplicate_paths": near_dups_dom,
        "conflict_stats": conflict_stats,
        "url_class_dist": url_df["binary_label"].value_counts().to_dict(),
        "dom_class_dist": dom_df["binary_label"].value_counts().to_dict(),
        "source_dist": combined_df["source"].value_counts().to_dict() if "source" in combined_df.columns else {},
        "taxonomy_dist": combined_df["threat_category"].value_counts().to_dict() if "threat_category" in combined_df.columns else {},
        "date_min": str(valid_dates.min().date()) if not valid_dates.empty else "N/A",
        "date_max": str(valid_dates.max().date()) if not valid_dates.empty else "N/A",
        "invalid_dates": int(parsed_dates.isna().sum()) if len(parsed_dates) else 0,
        "url_outliers": _numeric_outlier_summary(url_df, [c for c in url_feature_cols if c != "tld"]),
        "dom_outliers": _numeric_outlier_summary(dom_df, dom_feature_cols),
    }

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    src_lines = "\n".join(f"| `{k}` | {v:,} |" for k, v in summary["source_dist"].items())
    tax_lines = "\n".join(f"| `{k}` | {v:,} |" for k, v in summary["taxonomy_dist"].items())
    out_u_lines = "\n".join(
        f"| `{r['feature']}` | {r['mean']} | {r['median']} | {r['max']} | {r['extreme_outliers_3iqr']:,} |"
        for r in summary["url_outliers"]
    )
    out_d_lines = "\n".join(
        f"| `{r['feature']}` | {r['mean']} | {r['median']} | {r['max']} | {r['extreme_outliers_3iqr']:,} |"
        for r in summary["dom_outliers"]
    )

    md = f"""# WebShield AI v3.0 — Dataset Quality & Validation Report

**Generated At:** `{summary['generated_at']}`

---

## 1. Corpus Overview & Partition Separation

| Dataset File | Verified Rows | Unique Root Domains | Phishing / Malicious (`0`) | Benign (`1`) | Non-Binary (`-1`) | Null Cells |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `data/processed/url_dataset.csv` | {len(url_df):,} | {url_df['root_domain'].nunique():,} | {summary['url_class_dist'].get(0, 0):,} | {summary['url_class_dist'].get(1, 0):,} | 0 | {summary['url_missing_cells']} |
| `data/processed/dom_dataset.csv` | {len(dom_df):,} | {dom_df['root_domain'].nunique():,} | {summary['dom_class_dist'].get(0, 0):,} | {summary['dom_class_dist'].get(1, 0):,} | 0 | {summary['dom_missing_cells']} |
| `data/processed/uncertain_samples.csv` | {len(uncertain_df):,} | {uncertain_df['root_domain'].nunique() if not uncertain_df.empty else 0:,} | 0 | 0 | {len(uncertain_df):,} | {int(uncertain_df.isnull().sum().sum()) if not uncertain_df.empty else 0} |
| `data/processed/operational_status_samples.csv` | {len(operational_df):,} | {operational_df['root_domain'].nunique() if not operational_df.empty else 0:,} | 0 | 0 | {len(operational_df):,} | {int(operational_df.isnull().sum().sum()) if not operational_df.empty else 0} |

### Domain-Disjoint Splits (`verify_domain_disjoint` = PASS / 0 Overlap)
- **URL Splits:** Train `{len(u_tr):,}` (`{u_tr['root_domain'].nunique():,}` domains) | Val `{len(u_va):,}` (`{u_va['root_domain'].nunique():,}` domains) | Test `{len(u_te):,}` (`{u_te['root_domain'].nunique():,}` domains)
- **DOM Splits:** Train `{len(d_tr):,}` (`{d_tr['root_domain'].nunique():,}` domains) | Val `{len(d_va):,}` (`{d_va['root_domain'].nunique():,}` domains) | Test `{len(d_te):,}` (`{d_te['root_domain'].nunique():,}` domains)

---

## 2. Duplicate, Conflict & Timestamp Checks

- **Exact Duplicate URLs Removed Across Union:** `{conflict_stats.get('exact_duplicate_url_count', 0):,}`
- **Conflicting Binary Labels Resolved Across Multi-Source Merge:** `{conflict_stats.get('conflicting_url_count', 0):,}` (verified malicious signals prioritized over unverified/stale labels)
- **Near-Duplicate Path-Normalized URLs Observed:** URL corpus `{near_dups_url:,}` | DOM corpus `{near_dups_dom:,}`
- **Timestamp Coverage (`date` column):** `{summary['date_min']}` to `{summary['date_max']}` (invalid/missing dates: `{summary['invalid_dates']}`)

---

## 3. Source Distribution (`combined_dataset.csv`)

| Source | Verified Count |
| --- | ---: |
{src_lines}

---

## 4. 18-Category Threat Taxonomy Distribution

| Taxonomy Category | Verified Count |
| --- | ---: |
{tax_lines}

---

## 5. Numeric Feature Distribution & Extreme Outlier Audit (`> Q3 + 3*IQR`)

### URL Features (Top Variance / Outliers)
| Feature | Mean | Median | Max | Outliers (`> 3xIQR`) |
| --- | ---: | ---: | ---: | ---: |
{out_u_lines}

### DOM Features (Top Variance / Outliers)
| Feature | Mean | Median | Max | Outliers (`> 3xIQR`) |
| --- | ---: | ---: | ---: | ---: |
{out_d_lines}
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)
    return summary
