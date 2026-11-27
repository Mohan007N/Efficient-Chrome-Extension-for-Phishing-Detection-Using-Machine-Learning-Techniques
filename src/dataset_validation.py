"""
src/dataset_validation.py — Schema Validation, Leakage Prevention & Domain-Grouped Splitting

Ensures:
1. Consistent multi-label taxonomy across sources:
   benign, phishing, brand_impersonation, malware_distribution,
   credential_risk, payment_risk, deceptive_behavior, suspicious_redirect, unknown
2. Strict separation of verified ground-truth samples vs. uncertain/unverified samples.
3. Domain-grouped train/validation/test splits (GroupShuffleSplit) so pages from the
   same root domain never leak across evaluation partitions.
4. Temporal split support for date-stamped datasets (e.g., PhreshPhish).
"""

from __future__ import annotations

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

PROVENANCE_COLUMNS: tuple[str, ...] = (
    "url",
    "domain",
    "root_domain",
    "source",
    "collection_timestamp",
    "verification_status",
    "html_available",
    "primary_label",
    "risk_labels",
    "confidence",
    "evidence",
)

FORBIDDEN_CREDENTIAL_COLUMNS = {"password", "passwd", "cookie", "cookies", "token", "auth_token", "secret"}


def validate_dataset_schema(df: pd.DataFrame, required_columns: list[str], allow_empty: bool = False) -> dict:
    """Validate dataset integrity, forbidden credential fields, and required columns."""
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
    val_size: float = 0.10,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split a DataFrame into domain-disjoint train, validation, and test partitions
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
    Chronologically split timestamped data (train on earlier dates, test on later dates),
    dropping any overlapping test domains from training to keep evaluation strict.
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

