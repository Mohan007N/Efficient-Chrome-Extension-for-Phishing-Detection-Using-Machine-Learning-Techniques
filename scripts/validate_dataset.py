"""
scripts/validate_dataset.py — Dataset Schema, Provenance & Leakage Validator
"""

from __future__ import annotations

import json
import os
import sys

import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.dataset_validation import validate_dataset_schema, verify_domain_disjoint
from src.dom_features import DOM_FEATURE_COLUMNS
from src.features import URL_FEATURE_COLUMNS

REQUIRED_VERIFIED_COLS = [
    "id", "domain", "root_domain", "brand", "category", "ownership_type",
    "label", "verification_source", "verification_date", "confidence", "notes",
]
REQUIRED_PHISHING_COLS = [
    "original_url", "normalized_url", "root_domain", "threat_category",
    "source", "verification_status", "confidence",
]


def validate_all_datasets() -> dict:
    report: dict = {"status": "ok", "checks": {}}

    ver_path = os.path.join(PROJECT_ROOT, "data", "verified_domains.csv")
    if os.path.exists(ver_path):
        vdf = pd.read_csv(ver_path)
        info = validate_dataset_schema(vdf, REQUIRED_VERIFIED_COLS)
        bad_labels = set(pd.to_numeric(vdf["label"], errors="coerce").dropna().astype(int)) - {0, 1, 2, 3, 4}
        if bad_labels:
            raise ValueError(f"verified_domains.csv contains invalid labels: {sorted(bad_labels)}")
        report["checks"]["verified_domains"] = {**info, "labels": vdf["label"].value_counts().to_dict()}

    ph_path = os.path.join(PROJECT_ROOT, "data", "phishing_domains.csv")
    if os.path.exists(ph_path):
        pdf = pd.read_csv(ph_path)
        info = validate_dataset_schema(pdf, REQUIRED_PHISHING_COLS)
        if pdf["normalized_url"].str.contains(r"\.example(?:[/:]|$)", case=False, na=False).any():
            raise ValueError("Synthetic .example domain found inside real phishing_domains.csv!")
        report["checks"]["phishing_domains"] = info

    look_path = os.path.join(PROJECT_ROOT, "data", "synthetic_lookalikes.csv")
    if os.path.exists(look_path):
        ldf = pd.read_csv(look_path)
        if not ldf["root_domain"].astype(str).str.endswith(".example").all():
            raise ValueError("All synthetic_lookalikes.csv entries must use reserved .example domains!")
        report["checks"]["synthetic_lookalikes"] = {"rows": len(ldf)}

    mc_path = os.path.join(PROJECT_ROOT, "data", "processed", "multiclass_dataset.csv")
    if os.path.exists(mc_path):
        mdf = pd.read_csv(mc_path)
        bad_mc = set(pd.to_numeric(mdf["multiclass_label"], errors="coerce").dropna().astype(int)) - {0, 1, 2, 3, 4}
        if bad_mc:
            raise ValueError(f"multiclass_dataset.csv has invalid multiclass_label values: {sorted(bad_mc)}")
        report["checks"]["multiclass_dataset"] = {
            "rows": int(len(mdf)),
            "label_counts": mdf["multiclass_label"].value_counts().to_dict(),
        }

    u_tr = os.path.join(PROJECT_ROOT, "data", "processed", "url_train.csv")
    u_va = os.path.join(PROJECT_ROOT, "data", "processed", "url_val.csv")
    u_te = os.path.join(PROJECT_ROOT, "data", "processed", "url_test.csv")
    if all(os.path.exists(p) for p in (u_tr, u_va, u_te)):
        tr_df, va_df, te_df = pd.read_csv(u_tr), pd.read_csv(u_va), pd.read_csv(u_te)
        verify_domain_disjoint(tr_df, va_df, te_df, group_col="root_domain")
        validate_dataset_schema(tr_df, URL_FEATURE_COLUMNS + ["url", "root_domain", "binary_label"])
        report["checks"]["url_splits"] = {"train": len(tr_df), "val": len(va_df), "test": len(te_df), "disjoint": True}

    d_tr = os.path.join(PROJECT_ROOT, "data", "processed", "dom_train.csv")
    d_va = os.path.join(PROJECT_ROOT, "data", "processed", "dom_val.csv")
    d_te = os.path.join(PROJECT_ROOT, "data", "processed", "dom_test.csv")
    d_tm = os.path.join(PROJECT_ROOT, "data", "processed", "dom_temporal_test.csv")
    if all(os.path.exists(p) for p in (d_tr, d_va, d_te)):
        dt1, dt2, dt3 = pd.read_csv(d_tr), pd.read_csv(d_va), pd.read_csv(d_te)
        verify_domain_disjoint(dt1, dt2, dt3, group_col="root_domain")
        validate_dataset_schema(dt1, DOM_FEATURE_COLUMNS + ["url", "root_domain", "binary_label"])
        extra = {}
        if os.path.exists(d_tm):
            dtm = pd.read_csv(d_tm)
            verify_domain_disjoint(dt1, dt2, dtm, group_col="root_domain")
            verify_domain_disjoint(dt1, dt3, dtm, group_col="root_domain")
            extra["temporal"] = len(dtm)
        report["checks"]["dom_splits"] = {"train": len(dt1), "val": len(dt2), "test": len(dt3), **extra, "disjoint": True}

    return report


if __name__ == "__main__":
    print(json.dumps(validate_all_datasets(), indent=2))

